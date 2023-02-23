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
from django.shortcuts import render
from django.core.management import call_command
from django.utils import timezone
import json
import boto3
import logging
from vincepub.models import VUReport, VendorRecord, VulnerabilityNote, NoteVulnerability, Vendor, VendorVulStatus
from vincepub import serializers
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.conf import settings
import traceback

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def send_sns(vul_id, issue, error):
    subject = "%s: %s%s" % (issue, settings.CASE_IDENTIFIER, vul_id)
    try:
        client = boto3.client('sns', settings.AWS_REGION)
        response = client.publish(
            TopicArn=settings.VINCE_ERROR_SNS_ARN,
            Subject=subject,
            Message=error)
        logger.debug("Response:{}".format(response))

    except:
        logger.debug(traceback.format_exc())
        logger.debug('Error publishing to SNS')

# Create your views here.

@csrf_exempt
def generate_reminders(request):
    #we don't want to return 404s too many times so just return a success
    # for this periodic task
    return JsonResponse({'response':'success'}, status=200)

@csrf_exempt
def check_for_updates(request):
    logger.debug(request)
    if request.method == 'POST':
        try:
            body_unicode = request.body.decode('utf-8')
            body_data = json.loads(body_unicode)
            logger.debug(body_data)
            message = json.loads(body_data['Message'])
            logger.debug(message)
            if message.get("Event"):
                if message["Event"] == "s3:TestEvent":
                    return JsonResponse({'response':'success'}, status=200)
            obj_key = message['Records'][0]['s3']['object']['key']            
        except:
            error_msg = "%s \n %s" % (body_data, traceback.format_exc())
            send_sns('Error in update script', 'issue with json load of HTTP POST', error_msg)
            return render(request, 'vincepub/404.html', {}, status=404)
        s3 = boto3.resource('s3', settings.AWS_REGION)
        static_bucket = s3.Bucket(settings.AWS_STORAGE_BUCKET_NAME)
        obj = s3.Object(settings.S3_UPDATE_BUCKET_NAME, obj_key)
        if obj:
            logger.debug("reading %s to update record" % obj.key)
            fkey = obj.key
            body = obj.get()['Body'].read().decode('utf-8')
            if fkey.startswith("vu_"):
                ldata = json.loads(body)
                if ldata.get("vince"):
                    try:
                        report = VUReport.objects.filter(idnumber = ldata['idnumber']).first()
                        logger.debug(f"Publishing {settings.CASE_IDENTIFIER}{report.idnumber}:{report.name}") 
                        # first if there are any files that need copied/removed, do that first
                        if ldata.get('copy_files') and ldata.get('replace_files'):
                            replace_files = ldata.get('replace_files')
                            copy_files = ldata.get('copy_files')
                            for no, f in enumerate(copy_files):
                                logger.debug(f"Copying file {f}")
                                copy_source = {'Bucket': settings.KB_SHARED_BUCKET,
                                               'Key': f}
                                static_bucket.copy(copy_source, settings.AWS_LOCATION + "/" + f)
                                try:
                                    content = report.vulnote.content
                                    replace_link = f"{settings.STATIC_URL}{f}"
                                    logger.debug(f"Replacing file {replace_files[no]} in content with {replace_link}")
                                    content = content.replace(replace_files[no], replace_link)
                                    report.vulnote.content = content
                                    report.vulnote.save()
                                except:
                                    logger.debug("Problem with replacing vulnote content")
                                    logger.debug(traceback.format_exc())

                        if ldata.get('unchanged_files'):
                            logger.debug("rewriting urls for unchanged files")
                            unchanged_files = ldata.get('unchanged_files')
                            for no, f in enumerate(unchanged_files):
                                logger.debug(f"Rewriting URL for file {f}")
                                try:
                                    content = report.vulnote.content
                                    replace_link = f"{settings.STATIC_URL}{f}"
                                    logger.debug(f"Replacing file {unchanged_files[no]} in content with {replace_link}")
                                    content = content.replace(unchanged_files[no], replace_link)
                                    report.vulnote.content = content
                                    report.vulnote.save()
                                except:
                                    logger.debug("Problem with rewriting file URLS in vul note")
                                    logger.debug(traceback.format_exc())
                                
                        if ldata.get('remove_files'):
                            remove_files = ldata.get('remove_files')
                            for f in remove_files:
                                logger.debug(f"Removing file {f}")
                                s3.Object(settings.AWS_STORAGE_BUCKET_NAME, settings.AWS_LOCATION + "/" + f).delete()
                        if report:
                            call_command('rebuildnotes', ldata['idnumber'])
                            logger.debug("done building static file")                            
                            report.publish = True
                            report.save()
                            send_sns(ldata['idnumber'], "PUBLISHED", "Congratulations, the vulnote was published.")
                            return JsonResponse({'response':'success'}, status=200)
                        else:
                            raise Exception(f"no vulnote matched {ldata['idnumber']}")
                    except:
                        send_sns(ldata.get('cert_id'), "Problem building static vulnerability note", traceback.format_exc())
                        return JsonResponse({ 'problem': ldata['idnumber']}, status=500)

                elif ldata.get("kbpublisher"):
                    logger.debug(f"THIS IS A PUBLISHER GENERATED FILE {ldata['vuid']}")
                    try:
                        report = VUReport.objects.filter(idnumber = ldata['vuid']).exclude(vulnote__isnull=True).first()
                        if report:
                            if ldata.get('delete') == 1:
                                #THIS IS A DELETE REQUEST
                                report.delete()
                                #send_sns(ldata['vuid'], "PUBLISHED", "Success, the vulnerability note was removed.")
                                #now remove s3 static file
                                logger.debug(f"removing vuls/id/{ldata['vuid']}/index.html from bucket {settings.AWS_STORAGE_BUCKET_NAME}") 
                                s3.Object(settings.AWS_STORAGE_BUCKET_NAME, f"vuls/id/{ldata['vuid']}/index.html").delete()
                                s3.Object(settings.AWS_STORAGE_BUCKET_NAME, f"vuls/id/{ldata['vuid']}/").delete() 
                                return JsonResponse({'response':'success'}, status=200)
                                
                            logger.debug(f"Re-Publishing {settings.CASE_IDENTIFIER}{report.idnumber}:{report.name}")
                            report.vulnote.content = ldata['content']
                            report.vulnote.title = ldata['title']
                            if ldata['references']:
                                report.vulnote.references = ldata['references']
                            report.vulnote.revision_number = report.revision + 1
                            report.vulnote.dateupdated = timezone.now()
                            if ldata['publicdate']:
                                report.vulnote.publicdate = ldata['publicdate']
                            else:
                                report.vulnote.publicdate = timezone.now()
                            report.vulnote.save()
                            report.overview = ldata['content']
                            report.name = ldata['title']
                            report.dateupdated = timezone.now()
                            if ldata['references']:
                                report.public = ldata['references'].splitlines()
                            report.cveids = ldata['cveids']
                            report.revision = report.vulnote.revision_number
                            if ldata['publicdate']:
                                report.publicdate = ldata['publicdate']
                            else:
                                report.publicdate = timezone.now()
                            report.save()
                            vpnote = report.vulnote
                            
                        else:
                            logger.debug(f"Publishing for the first time {settings.CASE_IDENTIFIER}{ldata['vuid']}: {ldata['title']}")
                            vpnote = VulnerabilityNote(content = ldata['content'],
                                                       title = ldata['title'],
                                                       references = ldata['references'],
                                                       vuid=ldata['vuid'])

                            if ldata['publicdate']:
                                vpnote.publicdate = ldata['publicdate']
                            vpnote.save()
                            report, created = VUReport.objects.update_or_create(idnumber = ldata['vuid'],
                                                                                vuid = f"{settings.CASE_IDENTIFIER}{ldata['vuid']}",
                                                                                defaults={'name':ldata['title'],
                                                                                          'overview':ldata['content'],
                                                                                          'dateupdated':timezone.now(),
                                                                                          'vulnote':vpnote,
                                                                                          'cveids': ldata['cveids'],
                                                                                          'publicdate': ldata['publicdate']})
                            if ldata['references']:
                                report.public = ldata['references'].splitlines()

                            if created:
                                report.datefirstpublished = timezone.now()
                                report.save()
                            else:
                                vpnote.revision_number = report.revision + 1
                                vpnote.save()


                        # now update vuls/vendors/status
                        for vul in ldata['vuls']:
                            vp_vul = NoteVulnerability.objects.update_or_create(case_increment = vul['case_increment'],
                                                                                note=vpnote,
                                                                                defaults = {'cve': vul['cve'],
                                                                                            'description': vul['description'],
                                                                                            'uid':vul['uid']})
                        for vul in ldata['deleted_vuls']:
                                vp_vul = NoteVulnerability.objects.filter(case_increment = vul, note=vpnote).first()
                                if vp_vul:
                                    vp_vul.delete()

                        for vendor in ldata['vendors']:
                            vp_vendor, created = Vendor.objects.update_or_create(note=vpnote,
                                                                                 uuid=vendor['uid'],
                                                                                 defaults = {'contact_date': vendor['contact_date'],
                                                                                             'references': vendor.get('references'),
                                                                                             'statement': vendor.get('statement'),
                                                                                             'statement_date': vendor.get('statement_date'),
                                                                                             'addendum': vendor.get('addendum'),
                                                                                             'vendor': vendor['vendor']})
                            for status in vendor['status']:
                                vp_vul = NoteVulnerability.objects.filter(case_increment=status['vul_increment'],
                                                                          note=vpnote).first()
                                if vp_vul:
                                    intstatus = 3
                                    if status['status'] == "Affected":
                                        intstatus = 1
                                    elif status['status'] in ["Unaffected", "Not Affected"]:
                                        intstatus = 2
                                        
                                    vp_vulstatus = VendorVulStatus.objects.update_or_create(vendor=vp_vendor,
                                                                                            vul = vp_vul,
                                                                                            defaults={'status':intstatus,
                                                                                                      'references':status.get('references'),
                                                                                                      'statement':status.get('statement')})
                                    
                        vpnote.published=True
                        vpnote.save()

                        
                        for vendor in ldata['deleted_vendors']:
                            vp_vendor = Vendor.objects.filter(note=vpnote, uuid=vendor).first()
                            if vp_vendor:
                                vp_vendor.delete()

                        
                        if report:
                            call_command('rebuildnotes', ldata['idnumber'])
                            logger.debug("done building static file")
                            report.publish = True
                            report.save()
                            send_sns(ldata['cert_id'], "PUBLISHED", "Congratulations, the vulnote was published.")
                            return JsonResponse({'response':'success'}, status=200)
                    
                    except:
                        logger.debug(traceback.format_exc())
                        send_sns(ldata.get('cert_id'), "Problem building static vulnerability note", traceback.format_exc())
                        return JsonResponse({ 'problem': ldata['idnumber']}, status=500)


    data = {}
    return render(request, 'vincepub/404.html', data, status=404)
                        
"""
### this is PRE-VINCE old-school publishing
if ldata["DateFirstPublished"] == "":
ldata.pop("DateFirstPublished")
if ldata["PublicDate"] == "":
ldata.pop("PublicDate")
            if 'US-CERTTechnicalAlert' in ldata:
                ldata['uscerttechalert'] = ldata['US-CERTTechnicalAlert']
                ldata.pop("US-CERTTechnicalAlert")
            ldatalower = {k.lower(): v for k, v in ldata.items()}
            for key,val in ldatalower.items():
                    if key.startswith("txt_"):
                        k = key[4:]
                        ldatalower[k] = val
                        ldatalower.pop(key)
                ldatalower['name'] = ldatalower['name'].replace("&quot;", "\"")
                ldatalower['vuid'] = ldatalower['cert_id']
                ldatalower['idnumber'] = ldatalower['vuid'][3:]
                ldatalower['keywords_str'] = ", ".join(ldatalower['keywords'])
                ldatalower['cve_str'] = ", ".join(ldatalower['cveids'])
                ldatalower.pop('cert_id')
                record = VUReport.objects.filter(vuid=ldatalower['vuid']).first()
                report = None
                if (record):
                    #update record
                    logger.debug("UPDATE TO %s" % ldatalower['vuid'])
                    report = serializers.VUReportSerializer(record, data=ldatalower, partial=True)
                else:
                    #don't publish until static file created
                    ldatalower['publish'] = False
                    report = serializers.VUReportSerializer(data=ldatalower, partial=True)
                if (report.is_valid()):
                    report = report.save()
                    logger.debug("successfully imported %s" % ldatalower['vuid'])
                    s3.Object(settings.S3_UPDATE_BUCKET_NAME, fkey).delete()
                else:
                    send_sns(ldatalower['vuid'], "Error importing vul note", report.errors)
                    return JsonResponse({'vu problem': ldatalower['vuid']}, status=500)
            elif fkey.startswith("vendor"):
                ldata = json.loads(body)
                if ldata["NotifiedDate"] == "":
                    ldata.pop("NotifiedDate")
                else:
                    ldata["datenotified"] = ldata["NotifiedDate"]
                if ldata["StatementDate"] != "":
                    ldata["dateresponded"] = ldata["StatementDate"]
                ldatalower = {k.lower(): v for k, v in ldata.items()}
                for key,val in ldatalower.items():
                    if key.startswith("txt_"):
                        k = key[4:]
                        ldatalower[k] = val
                        ldatalower.pop(key)
                ldatalower['vuid'] = ldatalower['reference']
                ldatalower['idnumber'] = ldatalower['reference'][3:]
                ldatalower['vendorrecordid'] = ldatalower['idkey']
                ldatalower['datelastupdated'] = parse(ldatalower['datelastupdated'])
                vendor = VendorRecord.objects.filter(vendorrecordid=ldatalower['vendorrecordid']).first()
                record = None
                if (vendor):

                    logger.debug("updating vendor record for %s" % ldatalower['vendorrecordid'])
                    record = serializers.VendorRecordSerializer(vendor, data = ldatalower, partial=True)
                else:
                    record = serializers.VendorRecordSerializer(data = ldatalower, partial=True)

                if (record.is_valid()):
                    record.save()
                    logger.debug("successfully imported vendor record %s" % ldatalower['vendorrecordid'])
                    s3.Object(settings.S3_UPDATE_BUCKET_NAME, fkey).delete()
                else:
                    send_sns(ldatalower['vendorrecordid'], "importing vendor record", record.errors)
                    return JsonResponse({'vendor problem': ldatalower['vendorrecordid']}, status=500)

        call_command('rebuildnotes', ldatalower['idnumber'])
        logger.debug("done building static file")
        call_command('publish', '--no-delete')
        logger.debug("done publishing")
        report.publish = True
        report.save()
        send_sns(ldatalower['idnumber'], "PUBLISHED", "Congratulations, the vulnote was published.")
        return JsonResponse({'response':'success'}, status=200)
    else:
"""

@csrf_exempt
def vc_daily_digest(request):
    #we don't want to return 404s too many times so just return a success                                         
    # for this periodic task                                                                                      
    return JsonResponse({'response':'success'}, status=200)


@csrf_exempt
def vt_daily_digest(request):
    #we don't want to return 404s too many times so just return a success                                         
    # for this periodic task                                                                                      
    return JsonResponse({'response':'success'}, status=200)

