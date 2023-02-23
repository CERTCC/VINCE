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
from django.core.management import call_command
import sys
import os
import json
from vincepub.models import VUReport, NoteVulnerability, VulnerabilityNote, Vendor
from vincepub.serializers import *
from datetime import date
from dateutil.rrule import rrule, YEARLY
import requests
from django.conf import settings


START = date(1980, 1, 1)
END = date.today()

class Command(BaseCommand):
    help = 'Rebuild notes provided in the --in file'
    
    def add_arguments(self, parser):
        parser.add_argument('id', nargs='?', type=str, help='rebuild static vul note for this id.')
        parser.add_argument('--start', nargs='?', default='', type=str, const=True, help='Year to start')
        
    def handle(self, *args, **options):
        done = False
        
        try:
            if options['start']:
                start = date(int(options['start']),1,1)
            else:
                start = START

            for dt in rrule(YEARLY, dtstart=start, until=END):
                if options['id']:
                    notes = [f"{settings.CASE_IDENTIFIER}{options['id']}"]
                    if not(done):
                        done = True
                    else:
                        return
                else:
                    url = "https://{}/vuls/api/{}/summary/".format(settings.VINCEPUB_URL,dt.year)
                    r = requests.get(url)
                    rj = r.json()
                    notes = rj['notes']
                for note in notes:
                    #assumes case identifier ends with # - may need to change
                    vu,vuid = note.split('#')
                    note_url = "https://{}/vuls/notes/{}/".format(settings.VINCEPUB_URL,vuid)
                    rn = requests.get(note_url)
                    rnj = rn.json()
                    print("Updating %s" % rnj['vuid'])
                    vulnote = None
                    if rnj.get('vulnote'):
                        vulnote = rnj['vulnote']
                        # we need to pop the vulnote off so it doesn't get stuck in our DB
                        rnj.pop('vulnote')
                        
                    record = VUReport.objects.filter(vuid=rnj['vuid']).first()
                    if record:
                        report = VUReportSerializer(record, data=rnj, partial=True)
                    else:
                        report = VUReportSerializer(data=rnj, partial=True)
                    if (report.is_valid()):
                        record = report.save()
                    else:
                        print(record.errors)
                        return

                    #update vulnote if there is one
                    if vulnote:
                        note = VulnerabilityNote.objects.filter(vuid=vuid).first()
                        if note:
                            note.content = rnj['overview']
                            note.title = rnj['name']
                            if isinstance(rnj['public'], list):
                                note.references = "\n".join(rnj['public'])
                            else:
                                note.references = rnj['public']
                            note.dateupdated = rnj['dateupdated']
                            note.datefirstpublished = rnj['datefirstpublished']
                            note.revision_number = rnj['revision']
                            note.publicdate = rnj['publicdate']
                            note.save()
                        else:
                            # create a new one
                            note = VulnerabilityNote(vuid=vuid,
                                                     content = rnj['overview'],
                                                     title = rnj['name'],
                                                     dateupdated = rnj['dateupdated'],
                                                     datefirstpublished = rnj['datefirstpublished'],
                                                     revision_number = rnj['revision'],
                                                     publicdate = rnj['publicdate'])
                            if isinstance(rnj['public'], list):
                                note.references = "\n".join(rnj['public'])
                            else:
                                note.references = rnj['public']

                            note.save()
                            record.vulnote = note
                            record.save()
                    # else: content comes from vureporthtml saved
                            
                    #now get vendors
                    vendor_url = "https://{}/vuls/api/vendors/{}/".format(settings.VINCEPUB_URL,vuid)
                    rv = requests.get(vendor_url)
                    rvj = rv.json()
                    for vendor in rvj:
                        # change language of no statement
                        if vendor["statement"] == "No statement is currently available from the vendor regarding this vulnerability.":
                            #pop it
                            vendor["statement"] = None
                        elif vendor["statement"] == "We have not received a statement from the vendor.":
                            #pop it
                            vendor["statement"] = None
                        if vendor.get("addendum") == "There are no additional comments at this time.":
                            vendor["addendum"] = None
                        if vulnote:
                            #then use the Vendor
                            ov = Vendor.objects.filter(vendor=vendor['vendor'].strip(), note__vuid=vuid).first()

                            
                            if ov:
                                vendor['note'] = record.vulnote.id
                                rec = VendorSerializer(ov, data=vendor, partial=True)
                            else:
                                print("NEW VENDOR %s for %s" % (vendor['vendor'], vuid))
                                vendor['note'] = record.vulnote.id
                                
                                rec = VendorIngestSerializer(data=vendor, partial=True)
                            if (rec.is_valid()):
                                rec.save()
                            else:
                                print("ERROR SAVING VENDOR")
                                print(rec.errors)
                        else:
                            #use the vendorrecord
                            if 'vendorinformation' in vendor:
                                if vendor['vendorinformation'] == "We are not aware of further vendor information regarding this vulnerability":
                                    vendor["vendorinformation"] == None
                            
                            ov = VendorRecord.objects.filter(vendorrecordid=vendor['vendorrecordid']).first()
                            if ov:
                                rec = VendorRecordSerializer(ov, data=vendor, partial=True)
                            else:
                                rec = VendorRecordSerializer(data=vendor, partial=True)
                            if (rec.is_valid()):
                                rec.save()
                            else:
                                print("VENDOR RECORD ERRORS")
                                print(rec.errors)
                                return

                    if not vulnote:
                        continue
                    # also need vuls
                    vul_url = "https://{}/vuls/api/vuls/{}/".format(settings.VINCEPUB_URL,vuid)
                    rvuls = requests.get(vul_url)
                    rvlj = rvuls.json()
                    for vul in rvlj:
                        oldvul = NoteVulnerability.objects.filter(note__vuid=vuid, uid=vul['uid']).first()
                        vul['note'] = record.vulnote.id
                        if oldvul:
                            rec = VulSerializer(oldvul, data=vul, partial=True)
                            if (rec.is_valid()):
                                rec.save()
                            else:
                                print("ERROR SAVING VUL")
                                print(rec.errors)
                        else:
                            rec = NoteVulnerability(cve=vul['cve'],
                                                    description=vul['description'],
                                                    uid = vul['uid'],
                                                    case_increment=vul['case_increment'],
                                                    date_added=vul['date_added'],
                                                    dateupdated=vul['dateupdated'],
                                                    note=record.vulnote)
                            rec.save()

                    #vendor vul status
                    vendorvuls = "https://{}/vuls/api/vendors/vuls/{}/".format(settings.VINCEPUB_URL,vuid)
                    vvuls = requests.get(vendorvuls)
                    vvulsj = vvuls.json()
                    for vv in vvulsj:
                        ovendvul = VendorVulStatus.objects.filter(vendor__vendor=vv['vendor'],
                                                                  vul__uid=vv['vul']).first()
                        ven = Vendor.objects.filter(vendor=vv['vendor'].strip(), note__vuid=vuid).first()
                        vul = NoteVulnerability.objects.filter(note__vuid=vuid, uid=vv['vul']).first()
                        vv['vendor'] = ven.id

                        vv['vul'] = vul.id
                        if vv['status'] == "Affected":
                            vv['status'] = 1
                        elif vv['status'] in ["Not Affected", "Unaffected"]:
                            vv['status'] = 2
                        else:
                            vv['status'] = 3
                        if ovendvul:
                            vvs = VVSerializer(ovendvul, data=vv, partial=True)
                        else:
                            vvs = VVSerializer(data=vv, partial=True)

                        if (vvs.is_valid()):
                            vvs.save()
                        else:
                            print("ERROR SAVING VENDOR VUL STATUS")
                            print(vvs.errors)
                            return


        except KeyboardInterrupt:
            print("exiting...")
            sys.exit(0)
