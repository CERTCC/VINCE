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
import logging

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

from vince.lib import update_vinny_case, add_vul_vinny_case, add_coordinator_case, rm_vul_vinny_case, update_vc_vul_status, update_case_assignment, delete_case_assignment, vince_track_async_email, update_vinny_exploit, rm_vinny_exploit, update_vinny_cvss, update_vinny_cr, update_vinny_team_settings
from vince.models import VulnerabilityCase, Vulnerability, Contact, CaseArtifact, CaseAction, CaseMessageAction, UserSettings, FollowUp, VendorStatus, CaseAssignment, CaseRequest, VendorNotification, VulExploit, VulCVSS, GroupSettings
from vinny.models import VinceCommContact, VinceProfile
from vince.mailer import send_updatecase_mail, send_updateticket_mail
from django.conf import settings

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

@receiver(post_save, sender=VulnerabilityCase)
def update_case(sender, instance, created, **kwargs):
    if not(instance.lotus_notes):
        # don't move old cases into vincecomm
        update_vinny_case(instance)
    #add coordinator to case
    if instance.team_owner:
        add_coordinator_case(instance, instance.team_owner.groupsettings.contact)
            
    elif instance.owner:
        coord_group = instance.owner.groups.exclude(groupsettings__contact__isnull=True).first()
        if coord_group:
            logger.debug(coord_group.groupsettings.contact)
            add_coordinator_case(instance, coord_group.groupsettings.contact)
   
@receiver(post_save, sender=VendorStatus)
def update_vinny_vendorvulstatus(sender, instance, created, **kwargs):
    update_vc_vul_status(instance)

@receiver(post_save, sender=CaseRequest)
def update_case_request(sender, instance, created, **kwargs):
    if instance.case:
        update_case(sender, instance.case, created, **kwargs)
    else:
        update_vinny_cr(instance)
        
@receiver(post_save, sender=Vulnerability)
def update_vinny_vul(sender, instance, created, **kwargs):
    add_vul_vinny_case(instance.case, instance)

@receiver(post_delete, sender=Vulnerability)
def remove_vinny_vul(sender, instance, **kwargs):
    rm_vul_vinny_case(instance.case, instance)

@receiver(post_save, sender=VulCVSS)
def update_vinny_vul_cvss(sender, instance, created, **kwargs):
    update_vinny_cvss(instance)
    
@receiver(post_delete, sender=VulExploit)
def rm_vincecomm_exploit(sender, instance, **kwargs):
    rm_vinny_exploit(instance)
    
@receiver(post_save, sender=VulExploit)
def update_vincecomm_exploit(sender, instance, **kwargs):
    update_vinny_exploit(instance)
    
@receiver(post_save, sender=CaseAssignment)
def update_casecoordinator(sender, instance, created, **kwargs):
    update_case_assignment(instance)

@receiver(post_save, sender=VendorNotification)
def send_vendor_notification(sender, instance, created, **kwargs):
    if created:
        vince_track_async_email(instance)
    
@receiver(post_delete, sender=CaseAssignment)
def remove_casecoordinator(sender, instance, **kwargs):
    delete_case_assignment(instance)
    
@receiver(post_save, sender=Contact)
def update_contact(sender, instance, created, **kwargs):
    obj, created = VinceCommContact.objects.update_or_create(
        vendor_id=instance.id,
        defaults={'vendor_name': instance.vendor_name,
                  'vendor_type': instance.vendor_type,
                  'countrycode': instance.countrycode,
                  'active': instance.active,
                  'location': instance.location,
                  'uuid': instance.uuid})
    if not (created):
        obj.version = obj.version + 1
        obj.save()
        
@receiver(post_save, sender=CaseAction)
def send_action_mail(sender, instance, created, **kwargs):
    send_updatecase_mail(instance)

@receiver(post_save, sender=FollowUp)
def send_tix_action_mail(sender, instance, created, **kwargs):
    send_updateticket_mail(instance)

@receiver(post_save, sender=GroupSettings)
def update_team_settings(sender, instance, created, **kwargs):
    update_vinny_team_settings(instance)
    
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_usersettings(sender, instance, created, using, **kwargs):
    """                                                                                    
    Helper function to create UserSettings instances as                                    
    required, eg when we first create the UserSettings database                            
    table via 'syncdb' or when we save a new user.                                         
    If we end up with users with no UserSettings, then we get horrible                     
    'DoesNotExist: UserSettings matching query does not exist.' errors.                    
    """
    if using=='default' and created:
        from vince.settings import DEFAULT_USER_SETTINGS
        muser = UserSettings.objects.create(user=instance, settings=DEFAULT_USER_SETTINGS)
        muser.save()
    if using=='vincecomm' and created:
        from vinny.settings import DEFAULT_USER_SETTINGS
        muser = VinceProfile.objects.create(user=instance, settings=DEFAULT_USER_SETTINGS)
        muser.save()
        logger.debug("Successfully added USER %s to VINCE" % instance.email)


    
                                                                       
