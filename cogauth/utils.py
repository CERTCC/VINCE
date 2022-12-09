#########################################################################
# VINCE
#
# Copyright 2022 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
# AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
# MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
# WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a MIT (SEI)-style license, please see license.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for non-US
# Government use and distribution.
#
# Carnegie Mellon®, CERT® and CERT Coordination Center® are registered in the
# U.S. Patent and Trademark Office by Carnegie Mellon University.
#
# This Software includes and/or makes use of Third-Party Software each subject
# to its own license.
#
# DM21-1126
########################################################################

from django.conf import settings
from lib.warrant import Cognito
import boto3
from lib.warrant.aws_srp import AWSSRP
from boto3.exceptions import Boto3Error
from botocore.exceptions import ClientError, ParamValidationError
from django.core.exceptions import SuspiciousOperation
from jose import jwk, jwt
from jose.exceptions import JWTClaimsError, JWTError, ExpiredSignatureError
from jose.utils import base64url_decode
from vinny.models import VinceCommEmail, GroupContact, VinceCommInvitedUsers, VinceCommGroupAdmin, CaseMember
from vince.models import GroupSettings
from vinny.mailer import send_templated_mail
from django.contrib.auth.models import User, Group
import urllib
import json
import time
import logging
import traceback
import os
from bigvince.utils import get_cognito_url, get_cognito_pool_url

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

#verify token code based on
# https://github.com/awslabs/aws-support-tools/blob/master/Cognito/decode-verify-jwt/decode-verify-jwt.py

#now setup in settings.py
#keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(settings.COGNITO_REGION, settings.COGNITO_USER_POOL_ID)
#response = urllib.request.urlopen(keys_url)
#keys = json.loads(response.read())['keys']



def get_cognito(request):

    c = Cognito(settings.COGNITO_USER_POOL_ID,settings.COGNITO_APP_ID,
                user_pool_region=settings.COGNITO_REGION,
                access_token=request.session.get('ACCESS_TOKEN'),
                id_token=request.session.get('ID_TOKEN'),
                refresh_token=request.session.get('REFRESH_TOKEN'))
    changed = c.check_token()
    if changed:
        #verify token
        claims = token_verify(c.access_token, expire_fail=True)
        if claims:
            request.session['ACCESS_TOKEN'] = c.access_token
            request.session['REFRESH_TOKEN'] = c.refresh_token
            request.session['ID_TOKEN'] = c.id_token
            #request.session.save()
        else:
            #invalid token, remove access
            del(request.session['ACCESS_TOKEN'])
            del(request.session['REFERSH_TOKEN'])
            del(request.session['ID_TOKEN'])
            c = None
            raise SuspiciousOperation()
    return c

def token_verify(token, expire_fail=False):
    # get the kid from the headers prior to verification
    try:
        headers = jwt.get_unverified_headers(token)
    except:
        logger.debug("Error getting tokens")
        return False
    kid = headers['kid']
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(settings.COGNITO_KEYS)):
        if kid == settings.COGNITO_KEYS[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        logger.debug('Public key not found in jwks.json')
        return False

    kargs = {"issuer": get_cognito_pool_url(),
             'audience': settings.COGNITO_APP_ID}

    try:
        claims = jwt.decode(token, settings.COGNITO_KEYS[key_index], **kargs)
    except JWTClaimsError as e:
        logger.debug('JWT Claims failed decode')
        logger.debug(e)
        return False
    except ExpiredSignatureError as e:
        logger.debug('Decode Token expired, refresh next step')
        logger.debug(e)
        if expire_fail:
            return False
    except JWTError as e:
        logger.debug('JWT Signature is invalid')
        logger.debug(e)
        return False
    # THE BELOW MAY NOT BE NECESSARY since adding jwt.decode
    
    # construct the public key
    public_key = jwk.construct(settings.COGNITO_KEYS[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        logger.debug('Signature verification failed')
        return False
    #logger.debug('Signature successfully verified')
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims.get('client_id'):
        if claims['client_id'] != settings.COGNITO_APP_ID:
            logger.debug('Token was not issued for this audience')
            return False
    elif claims.get('aud'):
        # this is called aud in the ID_TOKEN, but client_id in the ACCESS TOKEN
        if claims['aud'] != settings.COGNITO_APP_ID:
            logger.debug('Token was not issued for this audience')
            return False
    # now we can use the claims
    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        logger.debug(f'Token is expired, refresh next step {claims["exp"]}')
        if expire_fail:
            return False
        return True
    return claims

def get_group(token):
    claims = token_verify(token, expire_fail=True)
    if claims:
        return claims.get('cognito:groups')
    return []

def cognito_add_user_to_group(user, group):
    logger.debug("Sending request")
    sns = boto3.client('sns',
             endpoint_url=get_cognito_pool_url(), region_name=settings.AWS_REGION)
    response = sns.publish(
        TargetArn=settings.VINCE_ERROR_SNS_ARN,
        Subject='Please add user to cognito group',
        MessageStructure='string',
	MessageAttributes={
            'Group': {
		'DataType': 'String',
                'StringValue': group,
            },
            'User': {
                'DataType': 'String',
                'StringValue': user.username
            }
        },
        Message="Please add user %s to the admin group" % user.username
    )


def cognito_admin_user(request):
    groups = get_group(request.session.get('ACCESS_TOKEN'))
    if groups:
        if settings.COGNITO_ADMIN_GROUP in groups:
            return True
    return False


def add_permissions(user):
    #check email in contact db, make sure email is active and contact is active
    user_allowed_groups = []
    email_contact = VinceCommEmail.objects.filter(email__iexact=user.email, email_list=False, status=True, contact__active=True)
    for contact in email_contact:
        logger.info(f"Found user { user.username } in contacts")
        user_allowed_groups.append(str(contact.contact.uuid))
        group = Group.objects.filter(name=contact.contact.uuid).first()
        if group:
            group.user_set.add(user)
            logger.info(f"Adding user { user.username } to group { group.name }")
            user.vinceprofile.pending = False
            user.vinceprofile.save()
        else:
            logger.info(f"Creating group { contact.contact.uuid } for { contact.contact.vendor_name }")
            group = Group(name=contact.contact.uuid)
            group.save()
            logger.info(f"Adding user { user.username } to group { group.name }")
            group.user_set.add(user)
            #Connecting Group to Contact
            gc = GroupContact(group=group,
                              contact=contact.contact)
            gc.save()
            user.vinceprofile.pending = False
            user.vinceprofile.save()
        groupadmin = VinceCommGroupAdmin.objects.filter(email=contact).first()
        if groupadmin:
            # this user is a group admin so add admin privileges
            ga = Group.objects.filter(name='vince_group_admin').first()
            if ga:
                ga.user_set.add(user)

    if len(email_contact) == 0:
        logger.info(f"No contact information on user { user.username }")
        
    # was this user [also] invited?
    vciu = VinceCommInvitedUsers.objects.filter(email__iexact = user.email)
    for u in vciu:
        group = Group.objects.filter(name=u.case.vuid).first()
        if group:
            group.user_set.add(user)
            logger.info(f"Adding user { user.username } to group { group.name }")
            user.vinceprofile.pending = False
            user.vinceprofile.save()
        else:
            logger.info(f"Creating group { u.case.vuid }")
            group = Group(name=u.case.vuid)
            group.save()
            logger.info(f"Adding user { user.username } to group { group.name }")
            group.user_set.add(user)
            user.vinceprofile.pending = False
            user.vinceprofile.save()
        member, created = CaseMember.objects.update_or_create(case=u.case,
                                                              participant=user,
                                                              defaults = {'coordinator': u.coordinator,
                                                                          'user': u.user, 
                                                                          'vince_id': u.vince_id,
                                                                          'group': group
                                                              })
        if created:
            logger.info(f"Adding user {user.username} to case {u.case.vuid}")
        else:
            logger.info(f"User already a member")

    if len(vciu) == 0:
        logger.info(f"User { user.username } was not invited to participate in case")

    #inventory vendor groups and remove any that this user shouldn't be apart of.
    user_groups = user.groups.exclude(groupcontact__isnull=True)
    for g in user_groups:
        if g.name not in user_allowed_groups:
            #this user must have been removed at some point, email was marked inactive,
            #or this contact became inactive
            logger.debug(g.name)
            logger.info(f"Removing {user.username} from group {g.name}: {g.groupcontact.contact}")
            g.user_set.remove(user)
            


def cognito_check_track_permissions(request):
    old_user = False
    groups = get_group(request.session.get('ACCESS_TOKEN'))
    if groups:
        vt_groups = settings.COGNITO_VINCETRACK_GROUPS.split(",")
        if list(set(vt_groups) & set(groups)):
            # if vtgroups and this user's group intersect:
            vincegroup = Group.objects.using('default').filter(name='vince').first()
            if vincegroup:
                if request.user.groups.filter(name='vince').exists():
                    old_user = True
                else:
                    vincegroup.user_set.add(request.user)

                
            if settings.COGNITO_SUPERUSER_GROUP in groups:
                request.user.is_superuser=True
                request.user.save()
            else:
                if request.user.is_superuser:
                    logger.warning("Downgrading permissions on %s" % request.user.username)
                    request.user.is_superuser=False
                    request.user.save()

                    
            for g in groups:
                #Does COGNITO group exist in VINCE?  If so, add the user to that track group.
                gs = GroupSettings.objects.filter(organization=g).first()
                if gs:
                    vgroup = gs.group
                    if request.user.groups.filter(name=vgroup.name).exists():
                        logger.info(f"User already in group {vgroup.name}")
                    else:
                        vgroup.user_set.add(request.user)
                        #set contact permissions
                        if (old_user==False):
                            # this is a new user - so give initial perms
                            request.user.usersettings.contacts_read = vgroup.groupsettings.contacts_read
                            request.user.usersettings.contacts_write = vgroup.groupsettings.contacts_write
                            request.user.usersettings.save()
                else:
                    if g not in settings.COGNITO_SUPERUSER_GROUP:
                        logger.info(f"LOCAL GROUP tied to Cognito group {g} doesn't exist")


            if settings.COGNITO_ADMIN_GROUP in groups:
                # if this user is in the admin group - make them staff
                request.user.is_staff=True
                request.user.save()
            return True
    else:
        #remove vt perms if exists
        if request.user.groups.filter(name='vince').exists():
            g = request.user.groups.filter(name='vince').first()
            g.user_set.remove(request.user)
        
    return False

        
def cognito_check_permissions(request):
    groups = get_group(request.session.get('ACCESS_TOKEN'))
    if groups:
        if settings.COGNITO_ADMIN_GROUP in groups:
            request.user.is_staff=True
            request.user.save()
            try:
                request.user.vinceprofile.pending = False
                request.user.vinceprofile.save()
            except:
                logger.debug("No vinceprofile, this is probably a VINCE system")
            
        if settings.COGNITO_SUPERUSER_GROUP in groups:
            request.user.is_superuser=True
            request.user.save()
        else:
            if request.user.is_superuser:
                logger.warning("Downgrading permissions on %s" % request.user.username)
                request.user.is_superuser=False
                request.user.save()

        logger.debug(settings.COGNITO_VINCETRACK_GROUPS)
        # if user has access to vincetrack
        logger.debug("CHECKING GROUPS")
        vt_groups = settings.COGNITO_VINCETRACK_GROUPS.split(",")
        if list(set(vt_groups) & set(groups)):
            vincetrackgroup = Group.objects.filter(name='vincetrack').first()
            if vincetrackgroup:
                vincetrackgroup.user_set.add(request.user)
            if settings.MULTIURL_CONFIG == False:
                # get user in vincetrack
                # this only works if the app has access to the VINCETrack database
                vincetrack_user = User.objects.using('default').filter(username=request.user.username).first()
                if not(vincetrack_user):
                    logger.debug("creating vincetrack user %s" % request.user.username)
                    vincetrack_user = User.objects.db_manager('default').create_user(username=request.user.username,
                                                                                     email=request.user.username,
                                                                                     first_name=request.user.first_name,
                                                                                     last_name=request.user.last_name,
                                                                                     is_active=True,
                                                                                     is_staff=True)
                
                    vincetrack_user.usersettings.preferred_username = request.user.vinceprofile.preferred_username
                    vincetrack_user.usersettings.save()
        gov_groups = settings.COGNITO_LIMITED_ACCESS_GROUPS.split(',')
        if list(set(gov_groups) & set(groups)):
            logger.debug("Checking for limited access group")
            vincelimited = Group.objects.filter(name="vince_limited").first()
            if vincelimited:
                vincelimited.user_set.add(request.user)
            
    #now check local contacts
    if settings.VINCE_NAMESPACE == "vinny":
        add_permissions(request.user)

    local_groups = request.user.groups.values_list('name',flat=True)
    if settings.COGNITO_ADMIN_GROUP in local_groups:
        if (groups == None) or not(settings.COGNITO_ADMIN_GROUP in groups):
            cognito_add_user_to_group(request.user, settings.COGNITO_ADMIN_GROUP)
            

    
def cognito_verify_email(request):
    client= boto3.client('cognito-idp',
             endpoint_url=get_cognito_url(),  region_name=settings.COGNITO_REGION)
    code = client.get_user_attribute_verification_code(AccessToken=request.session['ACCESS_TOKEN'],
                                                       AttributeName='email')
    print(code)


def cognito_verify_sms(request):
    client= boto3.client('cognito-idp',  endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)
    code = client.get_user_attribute_verification_code(AccessToken=request.session['ACCESS_TOKEN'],
                                                       AttributeName='phone_number')

def cognito_to_dict(attr_list,mapping):
    user_attrs = dict()
    for i in attr_list:
        name = mapping.get(i.get('Name'))
        if name:
            value = i.get('Value')
            user_attrs[name] = value
    return user_attrs


def password_challenge_dance(username, password, new_password):
    client = boto3.client('cognito-idp',  endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)
    aws = AWSSRP(username=username,
                 password=password,
                 pool_id=settings.COGNITO_USER_POOL_ID,
                 client_id=settings.COGNITO_APP_ID, client=client)
    try:
        tokens = aws.set_new_password_challenge(new_password)
    except (Boto3Error, ClientError) as e:
        error_code = e.response['Error']['Code']
        logger.debug(error_code)
        logger.debug(e.response['Error']['Message'])
        if error_code in [ 'NotAuthorizedException', 'UserNotFoundException']:
            return None

        return None
    return tokens

def mfa_challenge(request, code):
    
    client = boto3.client('cognito-idp',  endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)
    aws = AWSSRP(username=request.session['username'], password="abc",
                 pool_id=settings.COGNITO_USER_POOL_ID,
                 client_id=settings.COGNITO_APP_ID, client=client)
    if request.session['MFAREQUIRED'] == "SOFTWARE_TOKEN_MFA":
        tokens = aws.set_mfa_challenge(code, request.session['MFASession'])
    elif request.session['MFAREQUIRED'] == "SMS_MFA":
        tokens = aws.set_sms_challenge(code, request.session['MFASession'])
    else:
        return None

    claims = token_verify(tokens['AuthenticationResult']['IdToken'], expire_fail=True)
    if claims:
        claims = token_verify(tokens['AuthenticationResult']['AccessToken'], expire_fail=True)
        if claims:
            return tokens

    return None


def rm_mfa(request):
     client = boto3.client('cognito-idp',  endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)
     if request.session['MFAREQUIRED'] == "SOFTWARE_TOKEN_MFA":
         client.set_user_mfa_preference(
             SoftwareTokenMfaSettings={
                 'Enabled':False,
                 'PreferredMfa':False}, 
             AccessToken = request.session.get('ACCESS_TOKEN')
     )
     elif request.session['MFAREQUIRED'] == "SMS_MFA":
         client.set_user_mfa_preference(
             SMSMfaSettings={
                 'Enabled':False,
                 'PreferredMfa':False
             },
             AccessToken = request.session.get('ACCESS_TOKEN')
         )
     
def send_courtesy_email(template_name, user):
    s = user.vinceprofile.settings.get('email_preference', 1)
    if int(s) == 1:
        html = True
    else:
        html = False

    tmpl_context = {'team_signature': settings.DEFAULT_EMAIL_SIGNATURE}
    
    send_templated_mail(
        template_name,
	tmpl_context,
        recipients=user.email,
    )

def get_user_details(username):
    client = boto3.client('cognito-idp',  endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)

    res = client.admin_get_user(
        Username=username,
        UserPoolId=settings.COGNITO_USER_POOL_ID
    )   
    return(res)


def create_service_account(request):
    c = Cognito(settings.COGNITO_USER_POOL_ID, settings.COGNITO_APP_ID, user_pool_region=settings.COGNITO_REGION)
    c.add_base_attributes(email=request.POST['email'], preferred_username=request.POST['preferred_username'])
    try:
        c.register(request.POST['email'], request.POST['password1'])
    except (Boto3Error, ClientError) as e:
        error_code = e.response['Error']['Code']
        logger.debug(error_code)
        logger.debug(traceback.format_exc())
        if e.response['Error']['Code'] == 'InvalidPasswordException':
            return None, "Invalid Password"
        elif e.response['Error']['Code'] == 'UsernameExistsException':
            return None, "Email already exists."
        return None, error_code

    return True, None

def create_new_user(request, old_user=None):
    client = boto3.client('cognito-idp',  endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)
    messageaction = "SUPPRESS"
    if request.POST.get('send_email'):
        #user checked the box to send an email
        messageaction = None
        if old_user:
            messageaction = "RESEND"

    try:
        if messageaction:
            #this would work when the user is in FORCE_PASSWORD_CHANGE STATE
            res = client.admin_create_user(
                UserPoolId=settings.COGNITO_USER_POOL_ID,
                Username=request.POST['email'],
                UserAttributes=[
                {
                    'Name': 'preferred_username',
                    'Value': request.POST['preferred_username']
                },
                {
                    'Name': 'email',
                    'Value': request.POST['email'],
		},
                    {
                        'Name': 'email_verified',
                        'Value': 'True'
                    },
                ],
                TemporaryPassword=request.POST['password1'],
                DesiredDeliveryMediums=['EMAIL'],
                MessageAction=messageaction,
            )
        else:
            res = client.admin_create_user(
                UserPoolId=settings.COGNITO_USER_POOL_ID,
                Username=request.POST['email'],
                UserAttributes=[
                    {
                        'Name': 'preferred_username',
                        'Value': request.POST['preferred_username']
                    },
                    {
                        'Name': 'email',
                        'Value': request.POST['email'],
                    },
                    {
                        'Name': 'email_verified',
                    'Value': 'True'
                    },
                ],
                TemporaryPassword=request.POST['password1'],
                DesiredDeliveryMediums=['EMAIL'],
            )
        
        
    except ParamValidationError:
        return None, "Temporary Password is Unacceptable."
    except (Boto3Error, ClientError) as e:
        error_code = e.response['Error']['Code']
        logger.debug(error_code)
        logger.debug(traceback.format_exc())
        return None, error_code
    
    return res, None
        

def admin_change_user_details(request, old_email):
    client = boto3.client('cognito-idp',  endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)
    try:
        res = client.admin_update_user_attributes(
            UserPoolId=settings.COGNITO_USER_POOL_ID,
            Username=old_email,
            UserAttributes=[
                {
                    'Name': 'preferred_username',
                    'Value': request.POST['preferred_username']
                },
                {
                    'Name': 'email',
                    'Value': request.POST['email'],
                },
                {
                    'Name': 'email_verified',
                    'Value': 'True'
                },

            ],
        )

    except (Boto3Error, ClientError) as e:
        error_code = e.response['Error']['Code']
        logger.debug(error_code)
        logger.debug(traceback.format_exc())
        return None, error_code

    # change username/email for User
    #search user:
    user = User.objects.using('vincecomm').filter(username=old_email).first()
    if user:
        user.username=request.POST['email']
        user.email = request.POST['email']
        user.save()
        user.vinceprofile.preferred_username = request.POST['preferred_username']
        user.vinceprofile.save()
    #vincetrack user
    try:
        user = User.objects.filter(username=old_email).first()
        if user:
            user.username=request.POST['email']
            user.email = request.POST['email']
            user.save()
            user.usersettings.preferred_username = request.POST['preferred_username']
            user.usersettings.save()
    except:
        logger.debug("Not able to change vincetrack user")
        logger.debug(traceback.format_exc())
            
    
    return res, None


def disable_sms_mfa(username):
    client = boto3.client('cognito-idp',  endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)
    res = client.admin_set_user_mfa_preference(
        SMSMfaSettings={
            'Enabled': False,
            'PreferredMfa': False
        },  
        Username=username,
        UserPoolId=settings.COGNITO_USER_POOL_ID
    )   
    return


def disable_totp_mfa(username):

    client = boto3.client('cognito-idp',  endpoint_url=get_cognito_url(), region_name=settings.COGNITO_REGION)

    res = client.admin_set_user_mfa_preference(
        SoftwareTokenMfaSettings={
            'Enabled': False,
            'PreferredMfa': False
        },
        Username=username,
        UserPoolId=settings.COGNITO_USER_POOL_ID
    )
    return
