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
from django.core.management.base import BaseCommand, CommandError
from django.contrib import auth
from vince.models import *
from django.utils import timezone
from django.test import RequestFactory
import sys
import csv

class Command(BaseCommand):
    help = 'Load contact data from backup file into VINCE'

    def add_arguments(self, parser):
        parser.add_argument('in', nargs=1, type=str)

    def handle(self, *args, **options):

        f = open(options['in'][0], 'r', encoding='utf8')
        c = csv.reader(f, delimiter='\t')
        count = 0
        success = 0
        grouprows = []
        newcontact = True
        members = []
        phones = []
        keys = []
        status = True
        for row in c:
            if not len(row):
                count = count+1

                if not newcontact:

                    print(f"trying to update {srmail_peer_name}")
                    if int(lotus_id) == 0:
                        vendor_type = "Contact"
                        add_contact, created = Contact.objects.update_or_create(srmail_peer = srmail_peer_name,
                                                                                active = status,
                                                                                defaults={
                                                                                    'vendor_name':vendor_name,
                                                                                    'srmail_salutation':srmail_salutation,
                                                                                    'lotus_id':int(lotus_id),
                                                                                    'vendor_type':vendor_type,
                                                                                    'location':vendor_location})
                    else:
                        vendor_type = "Vendor"
                        try:
                            # try with just srmail peer name.  if that returns 2, then try with lotus_id
                            add_contact, created = Contact.objects.update_or_create(srmail_peer = srmail_peer_name,
                                                                                    defaults={
                                                                                        'vendor_name':vendor_name,
                                                                                        'srmail_salutation':srmail_salutation,
                                                                                        'vendor_type':vendor_type,
                                                                                        'location':vendor_location,
                                                                                        'lotus_id':int(lotus_id),
                                                                                        'active':status})
                        except:
                            add_contact, created = Contact.objects.update_or_create(srmail_peer = srmail_peer_name,
                                                                                    lotus_id = int(lotus_id),
                                                                                    defaults={
                                                                                        'vendor_name':vendor_name,
                                                                                        'srmail_salutation':srmail_salutation,
                                                                                        'vendor_type':vendor_type,
                                                                                        'location':vendor_location,
                                                                                        'active':status})

                    
                        #if created:
                        #print("------ADDING %s-----" % srmail_peer_name)

                    if add_contact.id:
                        for phone in phones:
                            phonenumber = phone[3]
                            try:
                                add_phone = PhoneContact.objects.update_or_create(contact=add_contact,
                                                                                  phone=phonenumber[phonenumber.find(' ')+1:],
                                                                                  defaults = {
                                                                                      'country_code':phonenumber[:phonenumber.find(' ')],
                                                                                      'phone_type':phone[2],
                                                                                      'comment':phone[4]})
                            except:
                                print("duplicate phone numbers")
                                pass

                        for member in members:
                            try:
                                add_email = EmailContact.objects.update_or_create(contact=add_contact,
                                                                                  email=member[0],
                                                                                  defaults = {
                                                                                      'name':member[1],
                                                                                      'email_function':member[2]})
                            except:
                                print("duplicate emails")
                                pass
                        for key in keys:
                            try:
                                add_pgp = ContactPgP.objects.update_or_create(contact=add_contact,
                                                                              pgp_key_id=key,
                                                                              defaults = {
                                                                                  'startdate':startdate,
                                                                                  'enddate':enddate,
                                                                                  'pgp_protocol':protocol})
                            except:
                                print("duplicate pgps")
                                pass
                                      
                        success=success+1
                    else:
                        print("ERROR COULD NOT ADD VENDOR")

                    newcontact=True
                    phones.clear()
                    members.clear()
                    keys.clear()
                    srmail_salutation = ""
                    lotus_id=0
                    startdate = ""
                    enddate = ""
                    protocol=""
                    status = True
                continue

            if row[0].startswith("#"):
                #this is a comment
                continue

            if row[0].startswith("+"):
                #this is a group
                #save for later since we need to evaluate contacts first
                grouprows.append(row)
                continue


            newcontact=False
            srmail_peer_name = row[0]

            if row[1] == "ORG":
                organization = row[2]
            elif row[1] == "VAR":
                if row[2] == "NAME":
                    vendor_name = row[3]
                elif row[2] == "salutation":
                    srmail_salutation = row[3]
                elif row[2] == "location":
                    vendor_location = row[3]
                elif row[2] == "VEND":
                    lotus_id = row[3]
            elif row[1] == "TO":
                members.append((row[2], row[3], "TO"))
            elif row[1] == "REPLYTO":
                members.append((row[2], row[3], "REPLYTO"))
            elif row[1] == "EMAIL":
                members.append((row[2], row[3], "EMAIL"))
            elif row[1] == "PHONE":
                phones.append(row)
            elif row[1] == "CRYPTO":
                startdate = row[2]
                enddate = row[3]
                if len(row) > 4:
                    protocol = row[4]
                if len(row) > 5:
                    for col in row[5:]:
                        if col.startswith("KEY="):
                            keys.append(col[col.find("=")+1:])
            elif row[1] == "CC":
                members.append((row[2], row[3], "CC"))
            elif row[1] == "STATUS":
                status = False
            else:
                print("NOT IMPLEMENTED %s" % row[1])

        save_for_later=[]
        for row in grouprows:

            name=row[0][1:]
            newgroup = ContactGroup.objects.filter(name=name).first()
            if newgroup:
                dupgroup = GroupDuplicate.objects.filter(group=newgroup)
            else:
                newgroup, created = ContactGroup.objects.update_or_create(srmail_peer_name=name,
                                                                 defaults = {'name': name,
                                                                             'description':name})
                if created:
                    dupgroup = GroupDuplicate(group=newgroup)
                    dupgroup.save()

            vendors=row[1].split()

            for vendor in vendors:
                search_contact = Contact.objects.filter(srmail_peer=vendor).first()
                if search_contact:
                    newmember, created = GroupMember.objects.update_or_create(group=newgroup, contact=search_contact,
                                                                              defaults={'member_type':search_contact.vendor_type})
                    #if created:
                    #    self.stdout.write(
                    #        self.style.SUCCESS("Successfully added %s to %s" % (search_contact.vendor_name, row[0])))
                else:
                    #search in groups
                    search_group = ContactGroup.objects.filter(name=vendor).first()
                    if search_group:
                        groupdup = GroupDuplicate.objects.filter(group=search_group).first()

                        groupingroup, created = GroupMember.objects.update_or_create(group=newgroup, group_member=groupdup,
                                                                                     defaults={'member_type':"Group"})
                        #if created:
                            #self.stdout.write(self.style.SUCCESS(
                            #    "Successfully added group %s to %s" % (vendor, row[0])))
                    else:
                        self.stdout.write("CANNOT FIND vendor %s" % vendor)
                        save_for_later.append((name, vendor))


        for vendor in save_for_later:
            search_group = ContactGroup.objects.filter(name=vendor[1]).first()
            if search_group:
                #big group
                group = ContactGroup.objects.filter(name=vendor[0]).first()

                groupdup = GroupDuplicate.objects.filter(group=search_group).first()
                groupingroup, created = GroupMember.objects.update_or_create(group=group, group_member=groupdup,
                                                                    defaults={'member_type':"Group"})
                #if created:
                #    self.stdout.write(self.style.SUCCESS(
                #        "Successfully added group %s to %s" % (vendor[1], vendor[0])))
            else:
                self.stdout.write("STILL CANNOT FIND vendor %s" % vendor[1])


        self.stdout.write(self.style.SUCCESS("Successfully read %d/%d contacts" % (success, count-1)))



