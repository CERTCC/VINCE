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
from datetime import date, datetime
import logging
from vinny.models import VinceCommEmail, ContactInfoChange, VinceCommContact, VendorAction
#from vince.lib import create_ticket
from vinny.lib import vince_comm_send_sqs
from django.urls import reverse
import gnupg
import traceback
import tempfile

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def send_ticket(change_list, contact, user):

    content = f"User: {user} made the following changes to the contact info for {contact.vendor_name}\n"
    content = content + "\n".join(map(str, change_list))

    logger.debug(content)
    vince_comm_send_sqs('EditContact', 'Contact', "None", user.username, contact.vendor_name, content)   
#    ticket = create_ticket("General", "Contact change for " + contact.vendor_name, content, user.username)
    

def send_ticket_groupadmin(change, contact, user):
    content = f"User: {user} made group administrator changes for {contact.vendor_name}\n"
    content = content + change.action.title

    logger.debug(content)
    vince_comm_send_sqs('EditContact', 'GroupAdmin', f"{change.id}", user.username, contact.vendor_name, content)
    
def create_contact_change(contact, model, field, old_value, new_value, user):
    
    action = VendorAction(title=f"{user.vinceprofile.vince_username} changed contact info for {contact.vendor_name}",
                          user=user)
    action.save()
    
    cic = ContactInfoChange(contact=contact,
                            model=model,
                            action=action,
                            field=field,
                            old_value=old_value,
                            new_value=new_value)
    cic.save()
    return cic


def change_email_contact(contact, old, new, user):

    changes = []
    
    if (old.email != new['email']):
        changes.append(create_contact_change(contact, "Email", "email address", old.email, new['email'], user))
    if (old.public != new['public']):
        changes.append(create_contact_change(contact, "Public", "public email", old.public, new['public'], user))
    if (old.email_type != new['email_type']):
        changes.append(create_contact_change(contact, "Email", "email type", old.email_type, new['email_type'], user))
    if (old.name != new['name']):
        changes.append(create_contact_change(contact, "Email", "email name", old.name, new['name'], user))
    return changes

def add_email_contact(contact, new, user):
    email_str = new['email'] + " ("+new['email_type']+") "
    if new['name']:
        email_str = email_str + new['name']
    cic = create_contact_change(contact, "Email", "NEW", None, email_str, user)
    return cic

def remove_email_contact(contact, old, user):
    email_str = old.email + " ("+old.email_type+") "
    if old.name:
        email_str = email_str + old.name
    cic = create_contact_change(contact, "Email", "REMOVED", email_str, None, user)
    return cic

def change_postal_contact(contact, old, new, user):
    changes = []

    if (old.country != new['country']):
        changes.append(create_contact_change(contact, "Postal", "country", old.country, new['country'], user))
    if old.primary != new['primary']:
        changes.append(create_contact_change(contact, "Postal", "primary", old.primary, new['primary'], user))
    if old.address_type != new['address_type']:
        changes.append(create_contact_change(contact, "Postal", "address_type", old.address_type, new['address_type'], user))
    if old.street != new['street']:
        changes.append(create_contact_change(contact, "Postal", "street", old.street, new['street'], user))
    if old.street2 != new['street2']:
        changes.append(create_contact_change(contact, "Postal", "street2", old.street2, new['street2'], user))
    if old.city != new['city']:
        changes.append(create_contact_change(contact, "Postal", "city", old.city, new['city'], user))
    if old.state != new['state']:
        changes.append(create_contact_change(contact, "Postal", "state", old.state, new['state'], user))
    if old.zip_code != new['zip_code']:
        changes.append(create_contact_change(contact, "Postal", "zip_code", old.zip_code, new['zip_code'], user))
    if (old.public != new['public']):
        changes.append(create_contact_change(contact, "Public", "public address", old.public, new['public'], user))
    return changes

def add_postal_contact(contact, new, user):
    postal_str = new['address_type'] + ":" + new['street'] + " ("+new['city']+") "+ new['state'] + " " + new['zip_code']
    cic = create_contact_change(contact, "Postal Address", "NEW", None, postal_str, user)
    return cic

def remove_postal_contact(contact, old, user):
    postal_str = old.address_type + ":" + old.street + " ("+old.city+") "+ old.state + " " + old.zip_code
    cic = create_contact_change(contact, "Postal Address", "REMOVED", postal_str, None, user)
    return cic

def change_phone_contact(contact, old, new, user):
    changes = []

    if old.country_code != new['country_code']:
        changes.append(create_contact_change(contact, "Phone", "country_code", old.country_code, new['country_code'], user))
    if old.phone != new['phone']:
        changes.append(create_contact_change(contact, "Phone", "phone", old.phone, new['phone'], user))
    if old.phone_type != new['phone_type']:
        changes.append(create_contact_change(contact, "Phone", "phone_type", old.phone_type, new['phone_type'], user))
    if old.comment != new['comment']:
        changes.append(create_contact_change(contact, "Phone", "comment", old.comment, new['comment'], user))
    if (old.public != new['public']):
        changes.append(create_contact_change(contact, "Public", "public phone", old.public, new['public'], user))
                       
    return changes

def add_phone_contact(contact, new, user):
    phone_str = new['phone_type'] + ":" + new['country_code'] + new['phone']
    if new['comment']:
        phone_str = phone_str + " (" + new['comment'] + ")"
    cic = create_contact_change(contact, "Phone", "NEW", None, phone_str, user)
    return cic

def remove_phone_contact(contact, old, user):
    phone_str = old.phone_type + ":" + old.country_code + old.phone
    if old.comment:
        phone_str = phone_str + " (" + old.comment + ")"
    cic = create_contact_change(contact, "Phone", "REMOVED", phone_str, None, user)
    return cic

def change_pgp_contact(contact, old, new, user):
    changes = []

    if old.pgp_key_id != new['pgp_key_id']:
        changes.append(create_contact_change(contact, "PGP Key", 'pgp_key_id', old.pgp_key_id, new['pgp_key_id'], user))
    if old.pgp_fingerprint != new['pgp_fingerprint']:
        changes.append(create_contact_change(contact, "PGP Key", 'pgp_fingerprint', old.pgp_fingerprint, new['pgp_fingerprint'], user))
    if old.pgp_version != new['pgp_version']:
        changes.append(create_contact_change(contact, "PGP Key", 'pgp_version', old.pgp_version, new['pgp_version'], user))
    if old.pgp_key_data != new['pgp_key_data']:
        changes.append(create_contact_change(contact, "PGP Key", 'pgp_key_data', old.pgp_key_data, new['pgp_key_data'], user))
    if old.revoked != new['revoked']:
        changes.append(create_contact_change(contact, "PGP Key", 'revoked', old.revoked, new['revoked'], user))
    if old.startdate != new['startdate']:
        changes.append(create_contact_change(contact, "PGP Key", 'startdate', old.startdate, new['startdate'], user))
    if old.enddate != new['enddate']:
        changes.append(create_contact_change(contact, "PGP Key", 'enddate', old.enddate, new['enddate'], user))
    if old.pgp_protocol != new['pgp_protocol']:
        changes.append(create_contact_change(contact, "PGP Key", 'pgp_protocol', old.pgp_protocol, new['pgp_protocol'], user))
    if (old.public != new['public']):
        changes.append(create_contact_change(contact, "Public", "public pgp", old.public, new['public'], user))
        
    if (old.pgp_email != new['pgp_email']):
        changes.append(create_contact_change(contact, "PGP Email", "pgp_email", old.pgp_email, new['pgp_email'], user))
        
    return changes


def extract_pgp_info(new):
    tf = tempfile.TemporaryDirectory()
    gpg = gnupg.GPG(gnupghome=tf.name)
    pgp_key_data = new.get('pgp_key_data')
    if pgp_key_data:
        try:
            import_result = gpg.import_keys(pgp_key_data)
            logger.debug(import_result.fingerprints)
            new['pgp_fingerprint'] = import_result.fingerprints[0]
            keys = gpg.list_keys()
            logger.debug(keys)
            newkey = next((item for item in keys if item['fingerprint'] == new['pgp_fingerprint']), None)
            logger.debug(newkey)
            if newkey:
                new['pgp_key_id'] = newkey['keyid']
                if newkey.get('expires') != "":
                    new['enddate'] = datetime.fromtimestamp(int(newkey['expires'])).strftime("%Y%m%d")
                elif newkey.get('subkey_info'):
                    #loop through subkeys
                    for sub in newkey['subkey_info']:
                        v = newkey['subkey_info'][sub]
                        if v.get('expires') != '':
                            if new.get('enddate'):
                                enddate = datetime.fromtimestamp(int(v['expires'])).strftime("%Y%m%d")
                                if enddate < new['enddate']:
                                    new['enddate'] = enddate
                            else:
                                new['enddate'] = datetime.fromtimestamp(int(v['expires'])).strftime("%Y%m%d")
                        else:
                            new['enddate'] = "INDEFINITE"
                else:
                    new['enddate'] = "INDEFINITE"
                new['startdate'] = datetime.fromtimestamp(int(newkey['date'])).strftime("%Y%m%d")
        except:
            logger.warning(traceback.format_exc())
            logger.warning("Could not parse PGP key")
            return None
    else:
        logger.debug("NO KEY DATA")
        return None
    return new

def xstr(s):
    if s is None:
        return ''
    return str(s)


def add_pgp_contact(contact, new, user):
    if new['pgp_key_id']:
        pgp_str = new['pgp_key_id'] + ":" + xstr(new['startdate'])  + " - " + xstr(new['enddate'])
        cic = create_contact_change(contact, "PGP", "NEW", None, pgp_str, user)
        return cic
    return None


def remove_pgp_contact(contact, new, user):
    if new.pgp_key_id:
        pgp_str = xstr(new.pgp_key_id) + ":" + xstr(new.startdate)  + " - " + xstr(new.enddate)
    else:
        pgp_str = "PGP key without key id"
    cic = create_contact_change(contact, "PGP", "REMOVED", pgp_str, None, user)
    return cic

def add_website(contact, new, user):
    if new['description']:
        web_str = new['url'] + ": " + new['description']
    else:
        web_str = new['url']
    cic = create_contact_change(contact, "Website", "NEW", None, web_str, user)
    return cic

def remove_website(contact, old, user):
    if old.description:
        web_str = old.url + ": " + old.description
    else:
        web_str = old.url
    cic = create_contact_change(contact, "Website", "REMOVED", web_str, None, user)
    return cic

def change_website_contact(contact, new, old, user):
    changes = []

    if old.url != new['url']:
        changes.append(create_contact_change(contact, "Website", "URL", old.url, new['url'], user))
    if old.description != new['description']:
        changes.append(create_contact_change(contact, "Website", "Description", old.description, new['description'], user))
    if (old.public != new['public']):
        changes.append(create_contact_change(contact, "Public", "public website", old.public, new['public'], user))
    return changes
