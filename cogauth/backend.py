#########################################################################
# VINCE
#
# Copyright 2023 Carnegie Mellon University.
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
import logging
from boto3.exceptions import Boto3Error
from botocore.exceptions import ClientError
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
try:
    from django.utils.six import iteritems
except:
    from six import iteritems
from django.contrib.auth.models import User
from lib.warrant import Cognito
from lib.warrant.exceptions import ForceChangePasswordException, SoftwareTokenException, SMSMFAException
from .utils import cognito_to_dict, password_challenge_dance
from .validator import TokenError, TokenValidator
import boto3
from lib.warrant.aws_srp import AWSSRP
import requests
from vinny.models import VinceAPIToken
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, TokenAuthentication, get_authorization_header
from django.utils.encoding import smart_text
from django.utils.translation import ugettext as _
import traceback
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)



class CognitoUser(Cognito):

    user_class = get_user_model()

    COGNITO_ATTRS = getattr(settings, 'COGNITO_ATTR_MAPPING',
                            { 'username': 'username',
                              'email':'email',
                              'given_name' : 'first_name',
                              'family_name':'last_name',
                              'locale':'country'
                              }
                            )

    def get_user_obj(self, username=None, attribute_list=[], metadata={}, attr_map={}):
        user_attrs = cognito_to_dict(attribute_list,CognitoUser.COGNITO_ATTRS)
        django_fields = [f.name for f in CognitoUser.user_class._meta.get_fields()]
        logger.debug(f"User attributes in Cognito is {user_attrs}")
        extra_attrs = {}
        # need to iterate over a copy
        for k, v in user_attrs.copy().items():
            if k not in django_fields:
                extra_attrs.update({k: user_attrs.pop(k, None) })
        if getattr(settings, 'COGNITO_CREATE_UNKNOWN_USERS', True):
            user, created = CognitoUser.user_class.objects.update_or_create(
                username=username,
                defaults=user_attrs)
            if user:
                if settings.VINCE_NAMESPACE == "vinny":
                    try:
                        for k, v in extra_attrs.items():
                            setattr(user.vinceprofile, k, v)
                            #logger.debug(f"{k}:{v}")
                        user.vinceprofile.save()
                    except Exception as e:
                        logger.debug(f"Vinceprofile probably doesn't exist for user {username}, error returned {e}")
                elif settings.VINCE_NAMESPACE == "vince":
                    try:
                        for k, v in extra_attrs.items():
                            setattr(user.usersettings, k, v)
                        user.usersettings.save()
                    except:
                        logger.debug(f"usersettings for {username} probably doesn't exist")
        else:
            try:
                user = CognitoUser.user_class.objects.get(username=username)
                for k, v in iteritems(user_attrs):
                    setattr(user, k, v)
                user.save()
            except CognitoUser.user_class.DoesNotExist:
                logger.debug(f"USER {username} DOES NOT EXIST")
                user = None
            if user:
                try:
                    for k, v in extra_attrs.items():
                        setattr(user.vinceprofile, k, v)
                    user.vinceprofile.save()
                except Exception as e:
                    logger.debug(f"vinceprofile probably does not exist for {username}, returned error is {e}")
                try:
                    for	k, v in	extra_attrs.items():
                        setattr(user.usersettings, k, v)
                    user.usersettings.save()
                except:
                    logger.debug(f"usersettings probably doesn't exist for {username}")
        return user

class CognitoAuthenticate(ModelBackend):
    def authenticate(self, request, username=None, password=None):
        if username and password:
            cognito_user = CognitoUser(
                settings.COGNITO_USER_POOL_ID,
                settings.COGNITO_APP_ID,
                user_pool_region=settings.COGNITO_REGION,
                access_key=getattr(settings, 'AWS_ACCESS_KEY_ID', None),
                secret_key=getattr(settings, 'AWS_SECRET_ACCESS_KEY', None),
                username=username)

            try:
                logger.debug(f"trying to authenticate {username}")
                cognito_user.authenticate(password)
            except ForceChangePasswordException:
                request.session['FORCEPASSWORD']=True
                request.session['username']=username
                return None
            except SoftwareTokenException as e:
                request.session['MFAREQUIRED']= "SOFTWARE_TOKEN_MFA"
                request.session['username']=username
                request.session['MFASession']=cognito_user.session
                request.session['DEVICE_NAME'] = str(e)
                request.session.save()
                return None
            except SMSMFAException:
                request.session['MFAREQUIRED']="SMS_MFA"
                request.session['username']=username
                request.session['MFASession']=cognito_user.session
                request.session.save()
                return None
            except (Boto3Error, ClientError) as e:
                error_code = e.response['Error']['Code']
                logger.debug(f"error authenticating user {username} error: {e} {error_code}")
                if error_code == "PasswordResetRequiredException":
                    logger.debug(f"reset password needed for {username}")
                    request.session['RESETPASSWORD']=True
                    request.session['username']=username
                    return None
                if error_code == "UserNotConfirmedException":
                    logger.debug(f"User {username} did not confirm their account")
                    #get user
                    user = User.objects.filter(username=username).first()
                    if user:
                        request.session['NOTCONFIRMED'] = True
                        request.session['CONFIRM_ID'] = user.id
                    return None
                if error_code in [ 'NotAuthorizedException', 'UserNotFoundException']:
                    return None
                else:
                    return None
        elif request.session.get('ACCESS_TOKEN'):
            # no password means we are either getting the code and trading it in
            # for tokens or we already have tokens - in which case we just need to get
            # the user and return

            client= boto3.client('cognito-idp', region_name=settings.COGNITO_REGION) 
            user = client.get_user(AccessToken=request.session['ACCESS_TOKEN'])
            # the username returned is the unique id, which doesn't help us since we use
            # emails for username - so get email and return CognitoUser
            email = list(filter(lambda email: email['Name'] == 'email', user['UserAttributes']))[0]['Value']
            username=email
            cognito_user = CognitoUser(
                settings.COGNITO_USER_POOL_ID,
                settings.COGNITO_APP_ID,
                user_pool_region=settings.COGNITO_REGION,
                access_key=getattr(settings, 'AWS_ACCESS_KEY_ID', None),
                secret_key=getattr(settings, 'AWS_SECRET_ACCESS_KEY', None),
                username=username)
            
            cognito_user.access_token= request.session['ACCESS_TOKEN']
            cognito_user.refresh_token = request.session['REFRESH_TOKEN']

        else:
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
            data = {
                'grant_type': 'authorization_code',
                'client_id': settings.COGNITO_APP_ID,
                'redirect_uri':settings.COGNITO_REDIRECT_TO,
                'code': username
            }
            r = requests.post(settings.COGNITO_OAUTH_URL, headers=headers,data=data)
            if not(r == None or (r.status_code != requests.codes.ok)):
                rj = r.json()
                access_token = rj['access_token']
                refresh_token = rj['refresh_token']
                id_token=rj['id_token']

                u = Cognito(settings.COGNITO_USER_POOL_ID, settings.COGNITO_APP_ID,
                            user_pool_region=settings.COGNITO_REGION,
                            id_token=id_token, refresh_token=refresh_token,
                            access_token=access_token)

                u.check_token()
                
                client= boto3.client('cognito-idp', region_name=settings.COGNITO_REGION)
                user = client.get_user(AccessToken=access_token)
                username = user['Username']
                cognito_user = CognitoUser(
                    settings.COGNITO_USER_POOL_ID,
                    settings.COGNITO_APP_ID,
                    user_pool_region=settings.COGNITO_REGION,
                    access_key=getattr(settings, 'AWS_ACCESS_KEY_ID', None),
                    secret_key=getattr(settings, 'AWS_SECRET_ACCESS_KEY', None),
                    username=username)
                
                cognito_user.verify_token(id_token, 'id_token', 'id')
                cognito_user.access_token= access_token
                cognito_user.refresh_token = refresh_token
                cognito_user.token_type = rj['token_type']
                
            else:
                return None
            
        # now we have a cognito user - set session variables and return
        if cognito_user:
            user = cognito_user.get_user()
            logger.debug(f"USER IS {user}")
        else:
            logger.debug("No user found for Cognito auth returning None")
            return None

        if user:
            request.session['ACCESS_TOKEN'] = cognito_user.access_token
            request.session['ID_TOKEN'] = cognito_user.id_token
            request.session['REFRESH_TOKEN'] = cognito_user.refresh_token
            #request.session.save()
            
        logger.info(f"USER {user} IS AUTHENTICATED!")
        return user


class CognitoAuthenticateAPI(ModelBackend):

    def authenticate(self, request):
        """For rest_framework if successfully authenticated using CognitoAuth
        the response wil include a tuple (request.user,request.auth)
        In case of Session based authentications 
        request.user will be a Django User instance.
        request.auth will be None.
        https://www.django-rest-framework.org/api-guide/authentication/        
        """
        try:
            user = CognitoAuthenticate().authenticate(request)
            if user:
                logger.info(f"API authentication using session for User {user} success")
                return user, None
            else:
                logger.warn(f"Failed API authentication using session for User {user} ")
                raise exceptions.AuthenticationFailed(_('Invalid API session attempted'))
        except Exception as e:
            logger.warn(f"Failed API authentication for session error is {e}")
            raise exceptions.AuthenticationFailed(_('Invalid API no session or token header was provided'))




class HashedTokenAuthentication(TokenAuthentication):
    """
    Simple token based authentication.
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Token ".  For example:
        Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a
    """
    model = VinceAPIToken

    def get_model(self):
        if self.model is not None:
            return self.model
        from rest_framework.authtoken.models import Token
        return Token

    """
    A custom token model may be used, but must have the following properties.
    * key -- The string identifying the token
    * user -- The user to which the token belongs
    """

    def authenticate_credentials(self, key):
        model = self.get_model()
        hashed_key = make_password(key, settings.SECRET_KEY)
        try:
            token = model.objects.select_related('user').get(key=hashed_key)
        except model.DoesNotExist:
            logger.warn(f"Failed API auth for token that does not exist {key}")
            raise exceptions.AuthenticationFailed(_('Invalid token.'))
        except Exception as e:
            logger.warn(f"Failed API auth for token Error {e}")
            raise exceptions.AuthenticationFailed(_('Unknown Token error.'))
            
        if not token.user.is_active:
            logger.warn(f"Failed API auth for {token.user} user is inactive or deleted")
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

        logger.info(f"Success user {token.user} is authenticated using API Token ")
        return (token.user, token)

    
class JSONWebTokenAuthentication(BaseAuthentication):
    """Token based authentication using the JSON Web Token standard."""

    def authenticate(self, request):
        """Entrypoint for Django Rest Framework"""
        jwt_token = self.get_jwt_token(request)
        logger.debug(f"JSOWEb token ookup for {jwt_token}")
        if jwt_token is None:
            return None

        # Authenticate token
        try:
            token_validator = self.get_token_validator(request)
            jwt_payload = token_validator.validate(jwt_token)
        except TokenError:
            raise exceptions.AuthenticationFailed()
        logger.debug(f"JSONWeb returned payload is {jwt_payload}")
        username=jwt_payload['email']
        user = User.objects.get(username=username)
        return (user, jwt_token)

    def get_jwt_token(self, request):
        logger.debug(f"Collected headers for JSONWwebToken as {request.headers}")
        auth = get_authorization_header(request).split()
        if not auth or smart_text(auth[0].lower()) != "bearer":
            return None

        if len(auth) == 1:
            msg = _("Invalid Authorization header. No credentials provided.")
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _(
                "Invalid Authorization header. Credentials string "
                "should not contain spaces."
            )
            raise exceptions.AuthenticationFailed(msg)

        return auth[1]


    def get_token_validator(self, request):
        return TokenValidator(
            settings.COGNITO_REGION,
            settings.COGNITO_USER_POOL_ID,
            settings.COGNITO_APP_ID,
        )
    
    def authenticate_header(self, request):
        """
        Method required by the DRF in order to return 401 responses for authentication failures, instead of 403.
        More details in https://www.django-rest-framework.org/api-guide/authentication/#custom-authentication.
        """
        return "Bearer: api"
    
    
            
