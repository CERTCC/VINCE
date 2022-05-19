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
from datetime import timedelta, date
from django import forms
# from django_summernote.widgets import SummernoteWidget, SummernoteInplaceWidget
# from django.utils.translation import gettext, gettext_lazy as _, pgettext_lazy
from django.utils.translation import gettext, gettext_lazy as _
from django_countries.widgets import CountrySelectWidget
from vince.lib import create_followup
from vince.lib import process_attachments, simple_merge, add_participant_vinny_case, add_coordinator_case, send_worker_email_all
from vince.mailer import send_newticket_mail, send_participant_email_notification
from django.conf import settings
from vinny.models import VTCaseRequest, CRFollowUp, VinceTrackAttachment, VinceAttachment, Case
# from django.utils import timezone
# from django.contrib.auth.forms import UserCreationForm
# from django.contrib.auth.models import User
from vince.models import *
from re import search
from django.core.exceptions import ValidationError
from vince.settings import DEFAULT_USER_SETTINGS, VULNOTE_TEMPLATE
from vince.permissions import get_user_gen_queue
import traceback
import os
from django.utils.encoding import smart_text
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)



class AllSearchForm(forms.Form):
    searchbar = forms.CharField(max_length=100, label='Keyword(s)', widget=forms.TextInput(), required=False)


class RolesForm(forms.Form):

    assigned_to = forms.ChoiceField(
	widget=forms.Select(attrs={'class': 'form-control'}),
        choices=(),
        required=False,
        label=_('Assign a User'),
    )


class TeamSettingsForm(forms.Form):

    outgoing_email = forms.EmailField(
	required=False,
	label=_('Outgoing Email Address'),
        widget=forms.TextInput(attrs={'class': 'form-control', 'readonly':'readonly'}),
	help_text=_('This is the email address that will be used to send official case notifications '
                    'to VINCE users. Editing this field requires superuser permissions.'),
    )

    vulnote_template = forms.CharField(
        widget=forms.Textarea(),
        label=_('Vulnerability Note Template'),
        initial=VULNOTE_TEMPLATE,
        required=False
    )

    team_signature = forms.CharField(
        widget=forms.Textarea(),
        label=_('Email Signature'),
        required=False
    )
    
    email_phone = forms.CharField(
        label=_("Phone number in email footer"),
        widget=forms.TextInput(attrs={'class': 'form-control', 'readonly':'readonly'}),
        required=False,
        help_text=_('Edit this in your team\'s public contact info in VINCEComm.'),
        max_length=20
    )

    email_email = forms.EmailField(
        required=False,
        label=_('Team email to use in email footer'),
        help_text=_('Edit this in your team\'s Public Contact Info in VINCEComm.'),
        widget=forms.TextInput(attrs={'class': 'form-control', 'readonly': 'readonly'}),
    )

    cna_email = forms.EmailField(
        required=False,
        label=_('Email to use for CVE assignment'),
        help_text=('If not set, this will default to the team email field above, or the default VINCE email if team email is not set.'),
        widget=forms.TextInput(attrs={'class':'form-control'})
    )
    
    disclosure_link = forms.URLField(
        required=False,
        label=_('Link to disclosure guidance'),
        help_text=_('Disclosure guidance is presented to case members at first view of case'),
    )

    def __init__(self, *args, **kwargs):
        super(TeamSettingsForm, self).__init__(*args, **kwargs)
	#if setting is not set for this user, set to default
        
    
class PreferencesForm(forms.Form):

    case_template = forms.ChoiceField(
        widget = forms.Select(attrs={'class': 'form-control'}),
        choices = (),
        required = False,
        label=_('Default Case Template'),
        help_text=_('All new cases created by you will use this case template.')
    )

    new_tickets = forms.MultipleChoiceField(
        choices=[],
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}))
        
    updated_tickets = forms.MultipleChoiceField(
        choices=[],
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}))

    email_case_changes = forms.MultipleChoiceField(
        choices=[(1, 'Immediately'), (2, 'Once Daily')],
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}),
        required=False)

    email_new_posts = forms.MultipleChoiceField(
	choices=[(1, 'Immediately'), (2, 'Once Daily')],
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}),
	required=False)

    email_new_messages = forms.MultipleChoiceField(
	choices=[(1, 'Immediately'), (2, 'Once Daily')],
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}),
	required=False)

    email_new_status = forms.MultipleChoiceField(
	choices=[(1, 'Immediately'), (2, 'Once Daily')],
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}),
	required=False)

    email_tasks = forms.MultipleChoiceField(
	choices=[(1, 'Immediately'), (2, 'Once Daily')],
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}),
	required=False)

    triage_role = forms.BooleanField(required=False)

    login_view_ticketlist = forms.BooleanField(
        label=_('Show Ticket List on Login?'),
        help_text=_('Display the ticket list upon login? Otherwise, the dashboard is shown.'),
        required=False,
    )

    email_on_ticket_change = forms.BooleanField(
        label=_('E-mail me on ticket change?'),
	required=False)

    email_on_ticket_assign = forms.BooleanField(
        label=_('E-mail me when assigned a ticket?'),
	required=False)

    tickets_per_page = forms.ChoiceField(
        label=_('Number of tickets to show per page'),
        help_text=_('How many tickets do you want to see on the Ticket List page?'),
        required=False,
        choices=((10, '10'), (25, '25'), (50, '50'), (100, '100')),
    )

    email_preference = forms.ChoiceField(
        choices=[(1, 'HTML'), (2, 'Plain Text')],
        label='Which email format do you prefer?',
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'}),
        required=False)


    reminder_tickets = forms.BooleanField(
        label=_('Remind me about tickets open > 14 days?'),
        required=False)

    reminder_publication = forms.BooleanField(
        label=_('Remind me about case expected publish dates?'),
        required=False)

    reminder_vendor_views = forms.BooleanField(
        label=_('Remind me about vendors that have not viewed a case?'),
        required=False)

    reminder_vendor_status = forms.BooleanField(
        label=_('Remind me about vendors that have not submitted status?'),
        required=False)

    reminder_cases = forms.BooleanField(
        label=_('Remind me about active cases that have not been modified > 14 days?'),
        required=False)
    
    def __init__(self, *args, **kwargs):
        super(PreferencesForm, self).__init__(*args, **kwargs)
        #if setting is not set for this user, set to default
        logger.debug(self.initial)
        if self.initial.get('templates'):
            self.fields['case_template'].choices = self.initial.get('templates')

        for x,y in DEFAULT_USER_SETTINGS.items():
            if self.initial.get(x) is None:
                if self.fields.get(x):
                    self.fields[x].initial=y
            else:
                if self.initial.get(x) == True:
                    #a lot of preferences have changed from T/F to multiple choice
                    if self.fields.get(x):
                        self.fields[x].initial = y


                    
class CreateVulNote(forms.Form):

    content = forms.CharField(
        widget=forms.Textarea(),
        label=_('Contents'),
        required=False,
        initial=VULNOTE_TEMPLATE
    )

    title = forms.CharField(
        label=_('Title'),
    )

    summary = forms.CharField(
        label=_('Revision comment'),
        help_text=_("Write a brief message for the vulnote history (change)log."),
        initial=_('Initial vul note.'),
        required = False)

    references = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 4}),
        label=_('References'),
        required=False,
        help_text=_("References should be valid URLs separated by a new line."))

    def __init__(self, *args, **kwargs):
        self.case = kwargs.pop("case")
        self.references = kwargs.pop('references')
        super(CreateVulNote, self).__init__(*args, **kwargs)
        self.fields['title'].initial = self.case.title
        self.fields['content'].initial = f"{VULNOTE_TEMPLATE}"
        self.fields['references'].initial = "\r\n".join(self.references)
        if self.case.team_owner:
            if self.case.team_owner.groupsettings.vulnote_template:
                if self.case.get_assigned_to:
                    self.fields['content'].initial = f"{self.case.team_owner.groupsettings.vulnote_template}This document was written by {self.case.get_assigned_to}.\r\n"
                else:
                    self.fields['content'].initial = f"{self.case.team_owner.groupsettings.vulnote_template}.\r\n"
        elif self.case.get_assigned_to:
            self.fields['content'].initial = f"{VULNOTE_TEMPLATE}This document was written by {self.case.get_assigned_to}.\r\n"

class VulNoteReviewForm(forms.Form):
    content = forms.CharField(
        widget=forms.Textarea(),
        label=_('Contents')
    )

    feedback = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 4}),
	label=_('Feedback'),
	required=False,
	help_text=_("General feedback/comments about this vulnerability note."))
    
    current_revision = forms.IntegerField(
	required=False,
        widget=forms.HiddenInput()
    )

    completed = forms.BooleanField(
        required=False,
        widget=forms.HiddenInput()
    )
    
    approved = forms.BooleanField(
        required=False,
        widget=forms.HiddenInput()
    )    

        
class EditVulNote(forms.Form):
    content = forms.CharField(
        widget=forms.Textarea(),
        label=_('Contents')
    )

    title = forms.CharField(
        label=_('Title'),
    )

    summary = forms.CharField(
        label=_('Revision comment'),
        help_text=_("Write a brief message for the vulnote history (change)log."),
        required = False)

    current_revision = forms.IntegerField(
        required=False,
        widget=forms.HiddenInput()
    )

    references = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 4}),
        label=_('References'),
        required=False,
        help_text=_("References should be valid URLs separated by a new line."))


    def __init__(self, request, current_revision, *args, **kwargs):
        self.request = request
        self.no_clean = kwargs.pop('no_clean', False)
        self.preview = kwargs.pop('preview', False)
        self.initial_revision = current_revision
        self.presumed_revision = None

        if current_revision:
            initial = {'content': current_revision.content,
                       'title': current_revision.title,
                       'references': current_revision.references,
                       'current_revision': current_revision.id}
            initial.update(kwargs.get('initial', {}))

            # Manipulate any data put in args[0] such that the current_revision
            # is reset to match the actual current revision.
            data = None
            if len(args) > 0:
                data = args[0]
                args = args[1:]
            if data is None:
                data = kwargs.get('data', None)
            if data:
                self.presumed_revision = data.get('current_revision', None)
                if not str(
                        self.presumed_revision) == str(
                        self.initial_revision.id):
                    newdata = {}
                    for k, v in data.items():
                        newdata[k] = v
                    newdata['current_revision'] = self.initial_revision.id
                    newdata['content'] = simple_merge(
                        self.initial_revision.content,
                        data.get(
                            'content',
                            ""))
                    newdata['title'] = current_revision.title
                    kwargs['data'] = newdata
                else:
                    # Always pass as kwarg
                    kwargs['data'] = data

            kwargs['initial'] = initial

        super().__init__(*args, **kwargs)

    def clean(self):
        """ 
        Validates form data by checking that no new revisions have been created
        while user attempted to edit
        """
        cd = super().clean()
        logger.debug(cd)
        if self.no_clean or self.preview:
            return cd
        if not str(self.initial_revision.id) == str(self.presumed_revision):
            raise forms.ValidationError(
                gettext('While you were editing, someone else changed the revision.'))
        if ('title' in cd) and cd['title'] == self.initial_revision.title and cd['content'] == self.initial_revision.content and cd['references'] == self.initial_revision.references:
            raise forms.ValidationError(gettext('No changes made. Nothing to save.'))
        return cd


class NotificationForm(forms.Form):
    title = forms.CharField(
        max_length=200,
        help_text=_('The subject of the email'),
    )

    email_template = forms.ChoiceField(
        choices=(),
	label="Choose an email template to send to the participant(s)",
        required=False)

    email_body = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control'}),
	label=_('Body of Email Notification'),
        help_text=_('This email template (participant_notify_newcase) already contains a greeting, a signature, and a link to the case.'),
        initial=settings.STANDARD_PARTICIPANT_EMAIL,
        required=True,
    )

    class Meta:
        fields = ('title', 'email_template', 'email_body')

    def save(self, cp):
        if cp.group:
            contact = Contact.objects.filter(vendor_name=cp.user_name).first()
            if contact:
                if cp.coordinator:
                    add_coordinator_case(cp.case, contact, cp)
                    followup = CaseAction(case = cp.case,
                                          title="Notified Coordinator Group: %s" % cp.user_name,
                                          date=timezone.now(),
                                          user = cp.added_by,
                                          action_type = 1)
                    followup.save()
                else:
                    followup = add_participant_vinny_case(cp.case, cp)
                #get email
                emails = contact.get_official_emails()
                followup.comment = self.cleaned_data['email_body']
                followup.save()
                for email in emails:
                    send_participant_email_notification([email], cp.case,
                                                        self.cleaned_data['title'],
                                                        self.cleaned_data['email_body'])
        else:
            vcuser = User.objects.using('vincecomm').filter(username=cp.user_name).first()
            if vcuser:
                send_participant_email_notification([cp.user_name], cp.case,
                                                    self.cleaned_data['title'],
                                                    self.cleaned_data['email_body'])
                followup = add_participant_vinny_case(cp.case, cp)
                followup.comment = self.cleaned_data['email_body']
                followup.save()
            else:
                send_participant_email_notification([cp.user_name], cp.case,
                                                    self.cleaned_data['title'],
                                                    self.cleaned_data['email_body'])
                followup = add_participant_vinny_case(cp.case, cp)
                followup.comment = self.cleaned_data['email_body']
                followup.save()
        cp.status = "Notified"
        cp.added_to_case = timezone.now()
        cp.save()



    
class VendorNotificationForm(forms.ModelForm):
    email_body = forms.CharField(
        widget=forms.Textarea(),
        label=_('Email Body'),
        help_text=_('This email template (vendor_notify_newcase) already contains a greeting (Hello), the team signature (configurable in team settings), and a link to the case.'),
        initial=settings.STANDARD_VENDOR_EMAIL,
        required=True)
    email_template = forms.ChoiceField(
        choices=(),
        label="Choose an email template to send to the vendor(s)",
        required=False)

    class Meta:
        model = VendorNotificationEmail
        fields = ('subject', 'email_template', 'email_body')

    def __init__(self, *args, **kwargs):
        super(VendorNotificationForm, self).__init__(*args, **kwargs)
        
    def save(self, user=None):

        email = VendorNotificationEmail(
            subject=self.cleaned_data['subject'],
            email_body = self.cleaned_data['email_body'])
        email.save()
        
        return email
            

class ShareVulNoteForm(forms.Form):
    content = forms.CharField(
        label="Post Content",
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-control'})
    )
    
    
class NewPostForm(forms.ModelForm):

    def __init__(self, *args, **kwargs):
        super(NewPostForm,self).__init__(*args, **kwargs)
        self.fields['version'].required=False
        self.fields['content'].required=False
    
    class Meta:
        model = VendorNotificationContent
        fields = ('content', 'version', )
        widgets = {
            'content': forms.Textarea(attrs={'class': 'form-control white-space:pre'}),
            'version': forms.HiddenInput()
            
            }


class UploadFileForm(forms.ModelForm):
    file = forms.FileField(
	required=False,
        label=_('Upload file'),
        widget=forms.FileInput(attrs={'class':'vulupload'})
    )

    case_id = forms.CharField(
        max_length=500,
    )

    pathname = forms.CharField(
        max_length=500,
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super(UploadFileForm, self).__init__(*args, **kwargs)

    class Meta:
        model = VinceFile
        fields = ('file',)

    def save(self):
        case = int(self.cleaned_data['case_id'])

        case = VulnerabilityCase.objects.filter(id=case).first()

        pathname = self.cleaned_data['pathname']
        
        file = self.cleaned_data['file']

        vulnote = False
        if 'notify' in pathname:
            pass
        else:
            vulnote = True

        logger.debug("IN FILE UPLOAD SAVE")
        #create the vincecommattachment
        if file.size:
            filename = smart_text(file.name)
            logger.debug(filename)
            try:
                mime_type = file.content_type
            except:
                mime_type = mimetypes.guess_type(filename, strict=False)[0]
                if not(mime_type):
                    mime_type = 'application/octet-stream'

            att = VinceAttachment(
                file=file,
		filename=os.path.basename(filename),
                mime_type=mime_type,
                size=file.size,
            )
            att.save(using='vincecomm')

            vc_case = Case.objects.filter(vuid=case.vuid).first()
            
            attach = VinceTrackAttachment(
                file = att,
                vulnote=vulnote,
                case=vc_case)
            attach.save(using='vincecomm')

            vf = VinceFile(user=self.user,
                           case = case,
                           filename=att.filename,
                           vulnote = vulnote,
                           comm_id=attach.id)
            vf.save()

            return vf
        return None
    
        
        
class AddArtifactForm(forms.ModelForm):
    taggles = forms.CharField(
        max_length=200,
        label='Tag(s)',
        required=False)

    attachment = forms.FileField(
        required=False,
        label=_('Attach File'),
        help_text=_('You can attach a file such as a document or screenshot to this ticket.'),
	widget=forms.FileInput(attrs={'class':'vulupload'})
    )
    is_file = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Is this a file?',
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'}),
        required=False)
        
    def __init__(self, *args, **kwargs):
        super(AddArtifactForm, self).__init__(*args, **kwargs)
        self.initial['is_file'] = False
        
    def _attach_files_to_follow_up(self, followup):
        files = self.cleaned_data['attachment']
        logger.debug(files)

        if files:
            files = process_attachments(followup, [files])
        return files

    class Meta:
        model = Artifact
        fields = ('is_file', 'attachment', 'type', 'title', 'value', 'description', 'taggles')
#        exclude = ('user', 'date_added', 'date_modified')
        widgets = {'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
                   'value': forms.Textarea(attrs={'class':'form-control', 'rows': 4})}

    def save(self, ticket=None, case=None, user=None):
        """ 
        Writes and returns an Artifact() object
        """
        if ticket:
            artifact = TicketArtifact(type = self.cleaned_data['type'],
                                      title = self.cleaned_data['title'],
                                      value = self.cleaned_data['value'],
                                      description = self.cleaned_data['description'],
                                      ticket=ticket)
        elif case:
            artifact = CaseArtifact(type = self.cleaned_data['type'],
                                    title = self.cleaned_data['title'],
                                    value = self.cleaned_data['value'],
                                    description = self.cleaned_data['description'],
                                    case=case)

        artifact.user = user
        artifact.save()

        if ticket:
            followup = create_followup(ticket=ticket,
                                       title="Added artifact",
                                       comment=self.cleaned_data['title'],
                                       artifact=artifact,
                                       user=user)
            followup.save()

        # Todo update this with action type.
        else:
            followup = CaseAction(case = case,
                                  title="Added artifact",
                                  date=timezone.now(),
                                  comment=self.cleaned_data['title'],
                                  artifact=artifact,
                                  action_type = 1,
                                  user=user)
            followup.save()

        files = self._attach_files_to_follow_up(followup)

        
        return artifact

class EditArtifactForm(forms.ModelForm):
    taggles = forms.CharField(
        max_length=200,
        label='Tag(s)',
        required=False)

    class Meta:
        model = Artifact
        exclude = ('user', 'date_added', 'date_modified', 'added_to_note', 'added_to_post')
        widgets = {'description': forms.Textarea(attrs={'class': 'form-control'}),}

class CaseCommunicationsFilterForm(forms.Form):
    keyword = forms.CharField(
        max_length=100,
        label='Keyword(s)',
        widget=forms.TextInput(attrs={'placeholder':'Keyword search'}),
        required=False)
    vendor = forms.MultipleChoiceField(
        choices=(),
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'})
    )
    participants = forms.MultipleChoiceField(
        choices = (),
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'})
        )
    communication_type = forms.MultipleChoiceField(
        choices=CaseAction.ACTION_TYPE,
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'})
    )
    datestart = forms.DateField(required=False)
    dateend = forms.DateField(required=False)
    timesort = forms.BooleanField(required=False)

    def __init__(self, *args, **kwargs):
        super(CaseCommunicationsFilterForm, self).__init__(*args, **kwargs)
        self.fields['dateend'].initial = timezone.now
        
class CaseFilterForm(forms.Form):

    
    STATUS_FILTER_CHOICES = (
        (VulnerabilityCase.ACTIVE_STATUS, _('Active')),
        (VulnerabilityCase.INACTIVE_STATUS, _('Inactive')),
        (3, _('Published')),
        (4, _('Unpublished')),
    )

    wordSearch = forms.CharField(
        max_length=100,
        label='Keyword(s)',
        widget=forms.TextInput(attrs={'placeholder':'Keyword/Tag search'}),
        required=False)
    status = forms.MultipleChoiceField(
        choices=STATUS_FILTER_CHOICES,
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}))

    team = forms.MultipleChoiceField(
        choices=(),
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'})
    )

    tag = forms.CharField(
        max_length=50,
        label='Tag',
        required=False,
        widget=forms.HiddenInput())
    
    page = forms.CharField(max_length=5,
                           required=False)

    datestart = forms.DateField(required=False)
    dateend = forms.DateField(required=False)
    owner = forms.MultipleChoiceField(
        choices=(),
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}))

    def __init__(self, *args, **kwargs):
        super(CaseFilterForm, self).__init__(*args, **kwargs)
        self.fields['dateend'].initial = timezone.now

class ActivityFilterForm(forms.Form):
    wordSearch = forms.CharField(
	max_length=100,
        label='Keyword(s)',
        widget=forms.TextInput(attrs={'placeholder':'Keyword search'}),
	required=False)
    user = forms.MultipleChoiceField(
        choices = (),
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'})
    )
    page = forms.CharField(max_length=5,
                           required=False)
    datestart = forms.DateField(required=False)
    dateend = forms.DateField(required=False)

    def __init__(self, *args, **kwargs):
        super(ActivityFilterForm, self).__init__(*args, **kwargs)
        self.fields['dateend'].initial = timezone.now
        now = timezone.now()
        self.fields['datestart'].initial = now - timedelta(days=7)
    
class TriageFilterForm(forms.Form):
    wordSearch = forms.CharField(
        max_length=100,
        label='Keyword(s)',
	widget=forms.TextInput(attrs={'placeholder':'Keyword search'}),
        required=False)
    queue = forms.MultipleChoiceField(
        choices=(),
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'})
    )
    page = forms.CharField(max_length=5,
                        required=False)
    datestart = forms.DateField(required=False)
    dateend = forms.DateField(required=False)

    def __init__(self, *args, **kwargs):
        super(TriageFilterForm, self).__init__(*args, **kwargs)
        self.fields['dateend'].initial = timezone.now
    
class TicketFilterForm(forms.Form):
    wordSearch = forms.CharField(
        max_length=100,
        label='Keyword(s)',
        widget=forms.TextInput(attrs={'placeholder':'Keyword/Tag search'}),
        required=False)
    queue = forms.MultipleChoiceField(
        choices=(),
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'})
    )
    team = forms.MultipleChoiceField(
        choices=(),
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'})
    )
    
    case = forms.MultipleChoiceField(
        choices=(),
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'})
    )
    tag = forms.CharField(
        max_length=50,
        label='Tag',
        required=False,
        widget=forms.HiddenInput())
    
    page = forms.CharField(max_length=5,
                           required=False)
    priority = forms.MultipleChoiceField(
        choices=Ticket.PRIORITY_CHOICES,
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}))
    status = forms.MultipleChoiceField(
        choices=Ticket.STATUS_CHOICES,
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}))
    datestart = forms.DateField(required=False)
    dateend = forms.DateField(required=False)
    owner = forms.MultipleChoiceField(
        choices=(),
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}))

    def __init__(self, *args, **kwargs):
        super(TicketFilterForm, self).__init__(*args, **kwargs)
        self.fields['dateend'].initial = timezone.now
    

#eventually add a create structured vul note...

class AbstractTicketForm(forms.Form):
    """
        Contain all the common code and fields between "TicketForm" and
        "PublicTicketForm". This Form is not intended to be used directly.
       """

    queue = forms.ChoiceField(
        widget=forms.Select(attrs={'class': 'form-control'}),
        label=_('Queue'),
        required=True,
        choices=()
    )

    title = forms.CharField(
        max_length=200,
        required=True,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label=_('Summary/Title'),
    )

    body = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control'}),
        label=_('Description'),
        required=True,
        help_text=_('Please be as descriptive as possible and include all details'),
    )

    priority = forms.ChoiceField(
        widget=forms.Select(attrs={'class': 'form-control'}),
        choices=Ticket.PRIORITY_CHOICES,
        required=True,
        initial='3',
        label=_('Priority'),
        help_text=_("Please select a priority carefully. If unsure, leave it as '3'."),
    )

    due_date = forms.DateTimeField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off'}),
        required=False,
        label=_('Due on'),
    )

    attachment = forms.FileField(
        required=False,
        label=_('Attach File'),
        help_text=_('You can attach a file such as a document or screenshot to this ticket.'),
        widget=forms.FileInput(attrs={'class':'vulupload'})
    )

    def _create_ticket(self):
        queue = TicketQueue.objects.get(id=int(self.cleaned_data['queue']))
        ticket = Ticket(title=self.cleaned_data['title'],
                        submitter_email=self.cleaned_data['submitter_email'],
                        created=timezone.now(),
                        status=Ticket.OPEN_STATUS,
                        queue=queue,
                        description=self.cleaned_data['body'],
                        priority=self.cleaned_data['priority'],
                        due_date=self.cleaned_data['due_date'],
                        )
        return ticket, queue

    def _create_follow_up(self, ticket, title, user=None):
        followup = FollowUp(ticket=ticket,
                            title=title,
                            date=timezone.now(),
                            comment=self.cleaned_data['body'],
                            )
        if user:
            followup.user = user
        return followup

    def _attach_files_to_follow_up(self, followup):
        files = self.cleaned_data['attachment']
        logger.debug(f"{self.__class__.__name__}: In _attach_files_to_follow_up. Files = {files}")
        if files:
            files = process_attachments(followup, [files])
        return files



class TicketForm(AbstractTicketForm):
    """
    Ticket Form creation for registered users.
    """
    submitter_email = forms.EmailField(
        required=False,
        label=_('Submitter E-Mail Address'),
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        help_text=_('This e-mail address will receive copies of all public '
                    'updates to this ticket.'),
    )

    assigned_to = forms.ChoiceField(
        widget=forms.Select(attrs={'class': 'form-control'}),
        choices=(),
        required=False,
        label=_('Assign a User'),
        help_text=_('If you select an owner other than yourself, they\'ll be '
                    'e-mailed details of this ticket immediately.'),
    )
    
    case = forms.CharField(
        max_length=250,
        label=_('Case'),
        required=False,
        help_text=_(f'If this ticket is associated with a specific Case, add it here. [{settings.CASE_IDENTIFIER}nnnnnn]'),
    )

    role = forms.ChoiceField(
        choices=(),
        label='Which role would you like to assign to this ticket?',
	widget=forms.RadioSelect(attrs={'class':'ul_nobullet'}),
	required=False)
    
    vulnote_approval = forms.IntegerField(required=False, widget=forms.HiddenInput())
    
    def __init__(self, *args, request=None, **kwargs):
        """
        Add any custom fields that are defined to the form.
        """
        super(TicketForm, self).__init__(*args, **kwargs)
        self.request = request


    def clean_case(self):
        data = self.cleaned_data['case']
        if data in [None, '', 'None']:
            return
        else:
            if data.startswith(settings.CASE_IDENTIFIER):
                data = data[len(settings.CASE_IDENTIFIER):]
            try:
                case = VulnerabilityCase.objects.get(vuid=data)
                return case
            except:
                raise forms.ValidationError("Invalid Case Selection")
        
    def save(self, user=None):
        """
        Writes and returns a Ticket() object
        """

        logger.debug(f"{self.__class__.__name__} save. Attachment: {self.cleaned_data['attachment']}")
        ticket, queue = self._create_ticket()
        if self.cleaned_data['assigned_to']:
            try:
                u = User.objects.get(id=self.cleaned_data['assigned_to'])
                ticket.assigned_to = u
            except User.DoesNotExist:
                ticket.assigned_to = None
        ticket.save()


        if self.cleaned_data['case']:
            case = self.cleaned_data['case']
            ticket.case = case
            ticket.save()
            if self.cleaned_data['vulnote_approval']:
                vulnote = VulNote.objects.filter(case=case).first()
                if vulnote:
                    vulnote.ticket_to_approve = ticket
                    vulnote.save()
            # create dependency
            dep = CaseDependency(case=case, depends_on=ticket)
            dep.save()

        if self.cleaned_data['assigned_to']:
            title = _('Ticket Opened & Assigned to %(name)s') % {
                'name': ticket.get_assigned_to or _("<invalid user>")
            }
        else:
            title = _('Ticket Opened')

        followup = self._create_follow_up(ticket, title=title, user=user)
        followup.save()
        logger.debug(f"followup: {followup}")
        files = self._attach_files_to_follow_up(followup)
        send_newticket_mail(followup, None, user=user)
        return ticket



class TicketCCForm(forms.ModelForm):
    ''' Adds either an email address or helpdesk user as a CC on a Ticket. Used for processing POST requests. '''

    class Meta:
        model = TicketCC
        exclude = ('ticket',)

    def __init__(self, *args, **kwargs):
        super(TicketCCForm, self).__init__(*args, **kwargs)
        if helpdesk_settings.HELPDESK_STAFF_ONLY_TICKET_CC:
            users = User.objects.filter(is_active=True, is_staff=True).order_by(User.USERNAME_FIELD)
        else:
            users = User.objects.filter(is_active=True).order_by(User.USERNAME_FIELD)
        self.fields['user'].queryset = users


class TicketCCUserForm(forms.ModelForm):
    ''' Adds a helpdesk user as a CC on a Ticket '''

    def __init__(self, *args, **kwargs):
        super(TicketCCUserForm, self).__init__(*args, **kwargs)
        if helpdesk_settings.HELPDESK_STAFF_ONLY_TICKET_CC:
            users = User.objects.filter(is_active=True, is_staff=True).order_by(User.USERNAME_FIELD)
        else:
            users = User.objects.filter(is_active=True).order_by(User.USERNAME_FIELD)
        self.fields['user'].queryset = users

    class Meta:
        model = TicketCC
        exclude = ('ticket', 'email',)


class TicketCCEmailForm(forms.ModelForm):
    ''' Adds an email address as a CC on a Ticket '''

    def __init__(self, *args, **kwargs):
        super(TicketCCEmailForm, self).__init__(*args, **kwargs)

    class Meta:
        model = TicketCC
        exclude = ('ticket', 'user',)

class CloseTicketForm(forms.Form):
    ''' Adds a close reason to a ticket '''

    close_choice = forms.ChoiceField(
        choices=Ticket.CLOSE_CHOICES,
        label=_("Provide reason"),
        required=False)
    send_email = forms.ChoiceField(
        choices=[(1, "No"), (2, 'Send Email'), (3, 'Send Message')],
        label=_("Notify Submitter?"),
        widget=forms.RadioSelect(attrs={'class': 'ul_nobullet'}),
        required=True)
    email_template = forms.ChoiceField(
        choices=(),
        label="Choose an email template to send to submitter",
        required=False)
    email = forms.CharField(
	label="Edit Email",
        widget=forms.Textarea(attrs={'rows': 8}),
        required=False)
    comment = forms.CharField(
        max_length=20000,
        widget=forms.HiddenInput(),
        required=False)
    new_status = forms.IntegerField(
        required=False,
        widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super(CloseTicketForm, self).__init__(*args, **kwargs)
        self.fields['send_email'].initial=1
        self.fields['close_choice'].initial = 2
    
class TicketDependencyForm(forms.ModelForm):
    ''' Adds a different ticket as a dependency for this Ticket '''

    class Meta:
        model = TicketDependency
        exclude = ('ticket',)

class CaseDependencyForm(forms.ModelForm):
    ''' Adds a different ticket as a dependency for this Case '''

    class Meta:
        model = CaseDependency
        exclude = ('case',)


WHY_NOT_CHOICES = [(1, 'Reporter has not attempted to contact any vendors'),
                   (2, 'Reporter is unable to find contact information for a vendor'),
                   (3, 'Other')]
YES_NO_CHOICES = [(1, "YES"), (2, "NO")]

class CreateCaseRequestForm(forms.ModelForm):
    ''' Creates a new case request '''
    ticket_ref = forms.IntegerField(required=False, widget=forms.HiddenInput())
    vrf_id = forms.CharField(widget=forms.HiddenInput(), required=False)
    date_submitted = forms.DateTimeField(widget=forms.HiddenInput(), required=False)
    title = forms.CharField(widget=forms.HiddenInput(), required=False)
    status = forms.IntegerField(required=False, widget=forms.HiddenInput())
    create_case = forms.IntegerField(
        widget=forms.HiddenInput(),
        required=False)
    
    queue = forms.IntegerField(
        widget=forms.HiddenInput(),
        label=_('Queue'),
        required=True,
    )
    share_release = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Do you want us to share your contact information with vendors?',
        help_text='We will share contact information with vendors unless otherwise specified.',
        required=False)
    credit_release = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Do you want to be acknowledged by name in any published document about this vulnerability?',
        help_text='If we publish a document based on this report, we will credit you unless otherwise specified.',
        required=False)
    comm_attempt = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Have you contacted the vendor about this vulnerability?',
        required=False)
    why_no_attempt = forms.ChoiceField(
        choices=WHY_NOT_CHOICES, label="Why has the vendor not been contacted directly?",
        widget=forms.RadioSelect(attrs={'class': 'ul_nobullet'}),
        required=False)
    first_contact = forms.DateField(
        label="Date of First Contact Attempt",
        input_formats=['%Y-%m-%d'],
        widget=forms.DateInput(attrs={'placeholder':'YYYY-MM-DD', 'autocomplete':'off'}),
        required=False)
    vul_exploited = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Is there evidence that this vulnerability is being actively exploited?',
        required=False)
    vul_public = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label="Is this vulnerability publicly known?",
        required=False)
    vul_disclose = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Do you plan to publicly disclose this vulnerability yourself?',
        required=False)
    disclosure_plans = forms.CharField(
        max_length=1000,
        label="What are your public disclosure plans? (max 1000 chars)",
        widget=forms.Textarea(attrs={'placeholder': 'Include dates and events if applicable'}),
        required=False)
    exploit_references = forms.CharField(
        max_length=20000,
        label="Please provide references",
        required=False,
        widget=forms.Textarea(attrs={'placeholder': 'URL(s)'}))
    public_references = forms.CharField(
        max_length=1000,
        label="Please provide references (max 1000 chars)",
        widget=forms.Textarea(attrs={'placeholder': 'URL(s)'}),
        required=False)
    request_type = forms.ChoiceField(
        choices=[(1, 'Vulnerability'),(3, 'US Gov Vulnerability')],
        label=_('What type of request is this?'),
        required=False)

    class Meta:
        model = CaseRequest
        exclude = ('search_vector', 'vc_id', 'close_reason')

    def __init__(self, *args, **kwargs):
        super(CreateCaseRequestForm, self).__init__(*args, **kwargs)
        self.fields['vul_public'].initial = False
        self.fields['vul_exploited'].initial = False

    def clean_queue(self):
        data = self.cleaned_data['queue']
        if data in [None, '', 'None']:
            return self.ValidationError("must pick a queue")
        else:
            queue = TicketQueue.objects.get(id=int(data))
            return queue

    def save(self, user=None, submission=None, queue=None):
        #submission is the full text returned from VRF
        #queue_name can be the name of a queue to save the CR in.
        logger.debug(self.cleaned_data)
#        case_fields = ['title', 'queue', 'created', 'modified', 'submitter_email', 'assigned_to', 'status', 'on_hold', 'description', 'resolution', 'priority', 'due_date']
#        for field in case_fields:
#            self.cleaned_data.pop(field)
#        logger.debug(self.cleaned_data)
        newCR = {}

        assigned_to = None
        
        if user:
            user_email = user.email
            assigned_to = user
        elif self.cleaned_data.get('contact_email'):
            user_email = self.cleaned_data.get('contact_email')
        else:
            user_email = ""
            
        if self.cleaned_data['share_release'] == "True":
            newCR['share_release'] = True
        else:
            newCR['share_release'] = False
        if self.cleaned_data['credit_release'] == "True":
            newCR['credit_release'] = True
        else:
            newCR['credit_release'] = False
        if self.cleaned_data['comm_attempt'] == "True":
            newCR['comm_attempt'] = True
        else:
            newCR['comm_attempt'] = False
        if self.cleaned_data['vul_public'] == "True":
            newCR['vul_public'] = True
        else:
            newCR['vul_public'] = False
        if self.cleaned_data['vul_disclose'] == "True":
            newCR['vul_disclose'] = True
        else:
            newCR['vul_disclose'] = False
        if self.cleaned_data['vul_exploited'] == "True":
            newCR['vul_exploited'] = True
        else:
            newCR['vul_exploited'] = False

            

        priority = 3
        due_date = None

        description = "New CR"
        
        if submission:
            description = submission
            
        ticket = None
        if self.cleaned_data.get('ticket_ref'):
            ticket = Ticket.objects.filter(id = int(self.cleaned_data['ticket_ref'])).first()
            if ticket:
                assigned_to = ticket.assigned_to
                priority = ticket.priority
                description = ticket.description
                if ticket.submitter_email:
                    user_email = ticket.submitter_email
                if ticket.due_date:
                    due_date = ticket.due_date
                else:
                    due_date = None
                

        if queue:
            logger.debug("GETTING QUEUE FROM PARAMETERS")
            ticketqueue = TicketQueue.objects.filter(id = queue).first()
        else:
            logger.debug("GETTING QUEUE FROM DATA")
            ticketqueue = self.cleaned_data['queue']
            
        if ticketqueue == None:
            logger.warning("NO QUEUE this will fail.")
        else:
            logger.debug("Adding CR on queue %s" % ticketqueue.title)

        
        newCase = CaseRequest(vrf_id = self.cleaned_data['vrf_id'],
                              share_release = newCR['share_release'],
                              credit_release = newCR['credit_release'],
                              comm_attempt = newCR['comm_attempt'],
                              vul_public = newCR['vul_public'],
                              vul_disclose = newCR['vul_disclose'],
                              vul_exploited = newCR['vul_exploited'],
                              contact_name = self.cleaned_data['contact_name'],
                              contact_org = self.cleaned_data['contact_org'],
                              contact_email = self.cleaned_data['contact_email'],
                              contact_phone = self.cleaned_data['contact_phone'],
                              why_no_attempt = self.cleaned_data['why_no_attempt'],
                              please_explain = self.cleaned_data['please_explain'],
                              vendor_name = self.cleaned_data['vendor_name'],
                              first_contact = self.cleaned_data['first_contact'],
                              vendor_communication = self.cleaned_data['vendor_communication'],
                              product_name = self.cleaned_data['product_name'],
                              product_version = self.cleaned_data['product_version'],
                              ics_impact = self.cleaned_data['ics_impact'],
                              vul_description = self.cleaned_data['vul_description'],
                              vul_exploit = self.cleaned_data['vul_exploit'],
                              vul_impact = self.cleaned_data['vul_impact'],
                              vul_discovery = self.cleaned_data['vul_discovery'],
                              public_references = self.cleaned_data['public_references'],
                              exploit_references = self.cleaned_data['exploit_references'],
                              disclosure_plans = self.cleaned_data['disclosure_plans'],
                              tracking = self.cleaned_data['tracking'],
                              comments = self.cleaned_data['comments'],
                              submission_type = self.cleaned_data['submission_type'],
                              multiplevendors = self.cleaned_data['multiplevendors'],
                              title = self.cleaned_data['product_name'],
                              queue = ticketqueue,
                              description = description,
                              submitter_email = user_email,
                              created=timezone.now(),
                              status = Ticket.OPEN_STATUS,
                              priority = priority)
        
            
        newCase.save()
        if assigned_to:
            newCase.assigned_to = assigned_to
            newCase.save()
            
        if due_date:
            newCase.due_date = due_date
            newCase.save()
            
        if self.cleaned_data['date_submitted']:
            newCase.date_submitted =  self.cleaned_data['date_submitted']
            newCase.save()
            
        if ticket:
            if ticket.case:
                newCase.case = ticket.case
                newCase.status = Ticket.CLOSED_STATUS
                newCase.save()
                tktcr = Ticket.objects.filter(id=newCase.id).first()
                newCase.case.case_request = tktcr
                newCase.case.save()

            ticket.delete()
        followup = FollowUp(ticket=newCase, title=_('Ticket Opened'), user=user)
        followup.save()

        send_newticket_mail(followup, None, user=user)
        
#        files = self._attach_files_to_follow_up(followup)
#        self._send_messages(ticket=newCase,
#                            queue=newCase.queue,
#                            followup=followup,
#                            files=files,
#                            user=user)

        return newCase
        
class CreateCaseForm(forms.ModelForm):
    ''' Creates a new case '''
    title = forms.CharField(
        max_length=100,
	required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        help_text='The title of this vulnerability note. (Can be changed later).',
        label=_('Title'),
    )
    summary = forms.CharField(
        max_length=1000,
	required=True,
        help_text='The placeholder text is taken from the description in the case request.',
        widget=forms.Textarea(attrs={'class': 'form-control'}),
        label=_('Summary'),
    )
    case_request = forms.IntegerField(
        required=False,
        widget=forms.HiddenInput())
    owner = forms.CharField(required=False, widget=forms.HiddenInput())
    created = forms.CharField(required=False, widget=forms.HiddenInput())
    vuid = forms.IntegerField(
        required=True,
        label=_('Case ID'),
        )
    template = forms.ChoiceField(
        widget=forms.Select(attrs={'class': 'form-control'}),
        choices=(),
        required=False,
        label=_('Use template'),
        help_text='Choose a template to automatically create tasks for this case (Optional)',
    )

    #YES the choices are backwards.  If lotus_notes is True then we won't be moving this case to Comm
    lotus_notes = forms.ChoiceField(
        choices=[(False, 'Yes'), (True, 'No')],
        label=_('Do you want to create this case in VINCEComm?'),
	help_text=_('If you check No, this case will not be created in VINCEComm (i.e. no collaborative coordination)'),
        required=True,
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'}))

    auto_assign = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label=_('Do you want to auto assign this case?'),
	help_text=_('You will be assigned this case unless you choose to auto assign it.'),
	required=True,
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'
}))

    role = forms.ChoiceField(
        choices=(),
        label='Which role would you like to assign to this case?',
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet'}),
        required=False)

    field_order = ['vuid', 'title', 'team_owner', 'product_name', 'product_version', 'summary', 'template', 'lotus_notes', 'auto_assign', 'role']


    def get_group_choices(self, user):
        return [(q.id , q.name) for q in user.groups.exclude(groupsettings__contact__isnull=True)]

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user")
        super(CreateCaseForm, self).__init__(*args, **kwargs)
        self.fields['product_version'].required=False
        self.fields['lotus_notes'].initial = False
        self.fields['auto_assign'].initial = False
        self.fields['team_owner'].choices = self.get_group_choices(user)
        
    class Meta:
        model = VulnerabilityCase
        exclude = ('created', 'owner', 'case_request', 'due_date', 'status', 'modified', 'on_hold', 'search_vector', 'vul_incrementer', 'publicdate', 'publicurl', 'changes_to_publish')
        
    def create_action(self, case, title, user=None):
        action = CaseAction(case=case,
                            title=title,
                            date=timezone.now(),
                            comment=self.cleaned_data['summary'],
                            action_type = 1)
        if user:
            action.user = user
        return action

    def clean_template(self):
        data = self.cleaned_data['template']
        if data in [None, '', 'None']:
            return None
        else:
            template = CaseTemplate.objects.get(id=int(data))
            return template


    def save(self, case=None, user=None, ticket=None):
        """
        Writes and returns a VulnerabilityCase() object
        """
        logger.debug("IN CASE FORM SAVE!!!")
        if self.cleaned_data['lotus_notes'] == 'True':
            lotus = True
        else:
            lotus = False

            
        newcase = VulnerabilityCase(title=self.cleaned_data['title'],
                                    summary=self.cleaned_data['summary'],
                                    case_request=case,
                                    product_name = self.cleaned_data['product_name'],
                                    product_version = self.cleaned_data['product_version'],
                                    owner=user,
                                    team_owner = self.cleaned_data['team_owner'],
                                    lotus_notes=lotus,
                                    created=timezone.now(),
                                    due_date = date.today()+timedelta(days=45), 
                                    vuid=self.cleaned_data['vuid'])
        newcase.save()

        #don't create a due date on a weekday
        if newcase.due_date.weekday() >= 5: #sunday = 6
            newcase.due_date = newcase.due_date+timedelta(days=(7-newcase.due_date.weekday()))
            newcase.save()
        
        assignment = CaseAssignment(assigned=user,
                                    case=newcase)
        assignment.save()
        title = _('Case Opened')
        action = self.create_action(newcase,title=title,user=user)
        action.save()

        if self.cleaned_data['template']:
            template = self.cleaned_data['template']
            newcase.template = template
            newcase.save()
            for task in CaseTask.objects.filter(template=template):
                ticket = Ticket(title = task.task_title,
                                created = timezone.now(),
                                status = Ticket.OPEN_STATUS,
                                queue = template.queue,
                                description = task.task_description,
                                priority = task.task_priority,
                                case = newcase)
                ticket.save()
                if task.assigned_to:
                    ticket.assigned_to = task.assigned_to
                    ticket.save()
                else:
                    # if the task is unassigned in the template,
                    # then assign it to the person creating the case
                    ticket.assigned_to = user
                    ticket.save()
                # create dependencies
                if task.dependency:
                    dep = CaseDependency(case=newcase, depends_on=ticket)
                    dep.save()
                title = _("Ticket Opened By %s Template" % template.title)
                fup = FollowUp(ticket=ticket,
                               title=title,
                               date=timezone.now(),
                               comment=task.task_title)
                if user:
                    fup.user = user
                fup.save()

        #now close caserequest
        if case:
            old_status_str = case.get_status_display()
            case.status = Ticket.CLOSED_STATUS
            case.case = newcase
            case.close_reason = 1
            case.save()
            comment = f"Closed case request. Created Case {settings.CASE_IDENTIFIER}{self.cleaned_data['vuid']}"
            title = "%s" % case.get_status_display()
            fup = FollowUp(ticket=case,
                           title=title,
                           date=timezone.now(),
                           comment=comment)
            if user:
                fup.user = user
            fup.save()
            c = TicketChange(
                followup=fup,
                field=_('Status'),
                old_value=old_status_str,
                new_value=case.get_status_display()
	    )
            c.save()
            # SEND EMAIL TO PARTICIPANT HERE!!!!
            # look up vrf in vincecomm so we can see if we can add submitter to participants
            cr = CaseRequest.objects.filter(id=case.id).first()
            if cr:
                vc_cr = VTCaseRequest.objects.filter(vrf_id=cr.vrf_id).first()
                if vc_cr:
                    if user:
                        vc_user = User.objects.using('vincecomm').filter(username=user.username).first()
                    else:
                        vc_user = None
                    
                    # update with new ID
                    vc_cr.new_vuid = newcase.vuid
                    vc_cr.status = VTCaseRequest.OPEN_STATUS
                    vc_cr.save()
                    
                    cr = CRFollowUp(cr = vc_cr,
                                    title = "Report status changed from Pending to Open",
                                    user = vc_user,
                                    comment = f"Case {settings.CASE_IDENTIFIER}{newcase.vuid} Opened")
                    cr.save()
                    
                    if vc_cr.user:
                        cp = CaseParticipant(case=newcase,
                                             user_name=vc_cr.user.username,
                                             added_by=user)
                        cp.save()
                        ca = CaseAction(case=newcase, title="Participant Auto-added to Case",
                                        user=user, action_type=1)
                        ca.save()
                    

        #create  case permissions        
        if case or ticket:
            if ticket:
                #this case was formed from a general ticket, use queue perms to determine
                #case perms
                case=ticket
            # get queue permissions and copy to case permissions
            perms = QueuePermissions.objects.filter(queue=case.queue)
            for perm in perms:
                # if you're creating a case from a CR,
                # permissions are transferred from the queue permissions
                cp = CasePermissions(case=newcase,
                                     group=perm.group,
                                     group_read=perm.group_read,
                                     group_write=perm.group_write,
                                     publish=perm.publish)
                cp.save()
        elif user:
            for group in user.groups.exclude(groupsettings__isnull=True):
                # if you're creating a case from scratch,
                # all members of your group have r/w and publish is disabled
                # a superuser can enable publish
                cp = CasePermissions(case=newcase,
                                     group=group,
                                     group_read=True,
                                     group_write=True,
                                     publish=group.groupsettings.publish)
                cp.save()
                
            
        
        return newcase
        
class EditCaseForm(forms.ModelForm):
    lotus_notes = forms.BooleanField(
        label=_('Do not create this case in VINCEComm.'),
        help_text=_('If you check this box, this case will never be transferred to VINCEComm (i.e. no collaborative coordination)'),
        required=False)

    publicdate = forms.DateTimeField(
        label=_('Date Public'),
        widget=forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off'}),
        help_text=_('The date this vulnerability became public.'),
        required=False)

    due_date = forms.DateTimeField(
        label=_('Due Date'),
        widget=forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off'}),
        help_text=_('Estimated Public Date'),
        required=False)
    
    field_order = ['vuid', 'title', 'product_name', 'product_version', 'summary', 'publicdate', 'publicurl', 'template', 'lotus_notes']
    
    class Meta:
        model = VulnerabilityCase
        exclude = ('vuid', 'created', 'modified', 'status', 'on_hold', 'case_request', 'search_vector', 'vul_incrementer', 'changes_to_publish')
        widgets = {
            'summary' : forms.Textarea(attrs={'rows': 4})
            }

    def get_group_choices(self, user):
        return [(q.id , q.name) for q in user.groups.exclude(groupsettings__contact__isnull=True)]

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user")
        super(EditCaseForm, self).__init__(*args, **kwargs)
        self.fields['team_owner'].choices = self.get_group_choices(user)

class AssignTicketTeamForm(forms.Form):

    team = forms.ChoiceField(
        choices=(),
        widget=forms.RadioSelect(attrs={'class': 'ul_nobullet'}),
        required=False,
        label=_('Assign a Team'),
    )

    reason = forms.CharField(
        widget=forms.Textarea(attrs={'placeholder': 'Provide reason for transfer'}),
        required=False,
        label=_('Reason for Transfer'),
    )

class RejectCaseTransferForm(forms.Form):

    reason = forms.CharField(
        widget=forms.Textarea(attrs={'placeholder': 'Provide reason for transfer rejection'}),
        required=True,
        label=_('Reason for Rejection of Transfer'),
    )
    
class RequestCaseTransferForm(forms.Form):

    team = forms.ChoiceField(
        choices=(),
        widget=forms.RadioSelect(attrs={'class': 'ul_nobullet'}),
	label=_('Assign a Team'),
    )

    reason = forms.CharField(
        widget=forms.Textarea(attrs={'placeholder': 'Provide reason for transfer'}),
        required=False,
        label=_('Reason for Transfer'),
    )
        

class VulCVSSForm(forms.ModelForm):

    class Meta:
        model = VulCVSS
        exclude = ('user', 'last_modified', 'vector', 'severity', 'score')
        widgets = {
            'vul': forms.HiddenInput()
        }

class EditTicketResolutionForm(forms.Form):

    resolution = forms.CharField(
        widget = forms.Textarea(),
        required=False)

        
class EditTicketForm(forms.ModelForm):

    case = forms.CharField(
        max_length=250,
	label=_('Case'),
        required=False,
	help_text=_(f'If this ticket is associated with a specific Case, add it here. [{settings.CASE_IDENTIFIER}nnnnnn]'),
    )

    due_date = forms.DateTimeField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off'}),
        required=False,
        label=_('Due on'),
    )

    class Meta:
        model = Ticket
        exclude = ('created', 'modified', 'status', 'on_hold', 'resolution', 'assigned_to', 'search_vector', 'close_reason')

    def __init__(self, *args, **kwargs):
        super(EditTicketForm, self).__init__(*args, **kwargs)

    def clean_case(self):
        data = self.cleaned_data['case']
        if data in [None, '', 'None']:
            return
        else:
            if data.startswith(settings.CASE_IDENTIFIER):
                data = data[len(settings.CASE_IDENTIFIER):]
            try:
                case = VulnerabilityCase.objects.get(vuid=data)
                return case
            except:
                raise forms.ValidationError("Invalid Case Selection")

class TicketContactForm(forms.ModelForm):

    contact = forms.CharField(
        max_length=250,
        label=_('Contact'),
        required=False,
        help_text=_('If this ticket is associated with a Contact, add it here.')
    )
    
    def clean_contact(self):
        data = self.cleaned_data['contact']
        if data in [None, '', 'None']:
            return
        try:
            contact = Contact.objects.filter(vendor_name=data, active=True).first()
            return contact
        except:
            print(traceback.format_exc())
            raise forms.ValidationError("Invalid Contact")

    def __init__(self, *args, **kwargs):
        super(TicketContactForm, self).__init__(*args, **kwargs)
            
    class Meta:
        model = TicketContact
        fields = ['id', 'contact']

class EditCaseRequestForm(forms.ModelForm):
    ticket_ref = forms.IntegerField(required=False, widget=forms.HiddenInput())
    share_release = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Do you want us to share your contact information with vendors?',
	help_text='We will share contact information with vendors unless otherwise specified.',
        required=True)
    first_contact = forms.DateField(
        label="Date of First Contact Attempt",
        input_formats=['%Y-%m-%d'],
        widget=forms.DateInput(attrs={'placeholder':'YYYY-MM-DD', 'autocomplete':'off'}),
        required=False)
    credit_release = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Do you want to be acknowledged by name in any published document about this vulnerability?',
        help_text='If we publish a document based on this report, we will credit you unless otherwise specified.',
        required=True)
    comm_attempt = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Have you contacted the vendor about this vulnerability?',
        required=True)
    why_no_attempt = forms.ChoiceField(
	choices=WHY_NOT_CHOICES, label="Why have you not contacted the vendor directly?",
        widget=forms.RadioSelect(attrs={'class': 'ul_nobullet'}),
        required=False)
    vul_exploited = forms.ChoiceField(
	choices=[(True, 'Yes'), (False, 'No')],
	label='Is there evidence that this vulnerability is being actively exploited?',
        required=True)
    vul_public = forms.ChoiceField(
	choices=[(True, 'Yes'), (False, 'No')],
	label="Is this vulnerability publicly known?",
	required=True)
    vul_disclose = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Do you plan to publicly disclose this vulnerability yourself?',
        required=True)
    disclosure_plans = forms.CharField(
        max_length=1000,
        label="What are your public disclosure plans? (max 1000 chars)",
        widget=forms.Textarea(attrs={'placeholder': 'Include dates and events if applicable'}),
        required=False)
    exploit_references = forms.CharField(
        max_length=20000,
        label="Please provide references",
        required=False,
        widget=forms.Textarea(attrs={'placeholder': 'URL(s)'}))
    public_references = forms.CharField(
        max_length=1000,
        label="Please provide references (max 1000 chars)",
	widget=forms.Textarea(attrs={'placeholder': 'URL(s)'}),
        required=False)    
    class Meta:
        model = CaseRequest
        exclude = ('created', 'modified', 'status', 'on_hold', 'resolution', 'assigned_to', 'title', 'description', 'priority', 'due_date', 'submitter_email', 'vrf_id', 'ticket_ptr_id', 'search_vector', 'request_type', 'close_reason', 'vc_id', 'case')
        widgets = {
            'queue':forms.HiddenInput()
        }


##### CONTACT FORMS ##########

class GroupForm(forms.ModelForm):
    group_select = forms.CharField(required=False, widget=forms.Select(choices=[]))

    def __init__(self, *args, **kwargs):
        super(GroupForm,self).__init__(*args, **kwargs)
        self.fields['version'].required=False

    def clean_srmail_peer_name(self):
        data = self.cleaned_data['srmail_peer_name']
        if not data.islower():
            raise forms.ValidationError("srmail peer names should be lowercase")
        if " " in data or "'" in data or '@' in data or '+' in data:
            raise forms.ValidationError("srmail peer names can not contain spaces, quotes, apostrophes, @, or +symbols")
        return data

    class Meta:
        model=ContactGroup
        fields=['name', 'description', 'group_select', 'comment', 'version']
        widgets = {
            'comment' : forms.Textarea(attrs={'rows': 4}),
            'version':forms.HiddenInput()
        }

class InitContactForm(forms.ModelForm):

    contact = forms.CharField(
        max_length=250,
        label=_('Contact'),
	help_text=_('The name of the vendor to verify with')
    )

    subject = forms.CharField(
        max_length=200,
        help_text=_('The subject of the email.'),
        )

    internal = forms.BooleanField(
        required = False,
        label=_('Internal Verification'),
        help_text=_('By checking this box, an email will not be sent but the email body will be logged in the ticket and should provide justification for why external verification is not needed.')
    )
    
    email_body = forms.CharField(
	widget=forms.Textarea(),
        label=_('Email Body'),
        required=True,
        initial=settings.STANDARD_EMAIL_SIGNATURE)

    ticket = forms.CharField(
        max_length=200,
        label=_('Ticket ID'),
        help_text=_('If this is related to an existing ticket, provide the ID here'),
        required=False)
    
    class Meta:
        model = ContactAssociation
        fields = ['contact', 'user', 'email', 'internal', 'subject', 'email_body', 'ticket']


    def clean_contact(self):
        data = self.cleaned_data['contact']
        print(data)
        if data in [None, '', 'None']:
            return
        contact = Contact.objects.filter(vendor_name=data).first()
        if contact:
            return contact
        else:
            raise forms.ValidationError("Invalid Contact")
        
    def clean_ticket(self):
        data = self.cleaned_data['ticket']
        if data in [None, '', 'None']:
            return
        try:
            ticket = Ticket.objects.get(id=data)
            return ticket
        except:
            raise forms.ValidationError("Invalid Ticket Selection. Use only numeric ID of Ticket.")
        
class ContactForm(forms.ModelForm):


    vtype = forms.ChoiceField(
        widget=forms.Select(attrs={'class': 'form-control'}),
        choices=(('User', 'User'), ('Vendor', 'Vendor'), ('Coordinator', 'Coordinator'), ('Group', 'Group')),
        required=True,
        label=_('Type'),
    ) 
    
    def __init__(self, *args, **kwargs):
        super(ContactForm, self).__init__(*args, **kwargs)
        self.fields['version'].required=False
        self.fields['vtype'].initial='Vendor'

    class Meta:
        model = Contact
        fields = ['vendor_name', 'vtype', 'countrycode', 'location', 'comment', 'version']
        widgets = {
            'comment' : forms.Textarea(attrs={'rows': 4}),
            'countrycode': CountrySelectWidget(layout='{widget}</div><div class="large-1 medium-1 columns"><img class="country-select-flag" id="{flag_id}" style="margin: 16px 4px 0" src="{country.flag}"></div>'),
            'version': forms.HiddenInput()
            }


class PostalForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(PostalForm, self).__init__(*args, **kwargs)
        self.fields['street2'].required=False
        self.fields['comment'].required=False
        self.fields['version'].required=False

    class Meta:
        model=PostalAddress
        fields = ['id', 'country', 'primary', 'address_type', 'street', 'street2', 'city', 'state', 'zip_code', 'comment', 'version']
        widgets = {'id': forms.HiddenInput(),
                   'version': forms.HiddenInput()}


class PhoneForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(PhoneForm, self).__init__(*args, **kwargs)
        self.fields['comment'].required=False
        self.fields['version'].required=False

    class Meta:
        model=PhoneContact
        fields = ['id', 'country_code', 'phone', 'phone_type', 'comment', 'version']
        widgets = {'id': forms.HiddenInput(), 'version': forms.HiddenInput()}


class EmailContactForm(forms.ModelForm):

    email_type = forms.ChoiceField(                                       
        choices=[('User', 'User'), ('Notification', 'Notification Only')],
        label='Is this a user or notification-only email address?',
        required=False,
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'}))                         
    
    def __init__(self, *args, **kwargs):
        super(EmailContactForm, self).__init__(*args, **kwargs)
        self.fields['version'].required=False
        self.fields['email_list'].required=False
        self.fields['name'].required = False
        self.fields['email_function'].required=False
        self.fields['email_function'].initial = "TO"
        self.fields['email_type'].initial='User'

    def clean_email(self):
        email = self.cleaned_data['email']
        if email:
            email = email.strip()
        return email

    def clean_name(self):
        name = self.cleaned_data['name']
        if name:
            name = name.strip()
        else:
            raise forms.ValidationError("Please provide a name with each email address.")
        return name

    class Meta:
        model = EmailContact
        fields = ['id', 'email', 'email_type', 'name', 'email_function', 'status', 'version', 'email_list', 'email_type']
        widgets = {'version':forms.HiddenInput() }

class WebsiteForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(WebsiteForm,self).__init__(*args, **kwargs)
        self.fields['version'].required=False

    class Meta:
        model = Website
        fields = ['url', 'description', 'version']
        widgets = {'version':forms.HiddenInput() }


def pgp_validator(key_data):
    if key_data:
        key_data = key_data.strip()
    if key_data == '':
        return key_data
    # validate start and end identifiers                                                                                  
    if not key_data.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
        raise ValidationError("PGP Key Data must begin with valid BEGIN line")
    if not key_data.endswith("-----END PGP PUBLIC KEY BLOCK-----"):
        raise ValidationError("PGP Key Data must end with valid END line")

    # find where the key data starts and ends                                                                             
    key_text_start = key_data.find("\n\n")
    if key_text_start > 0:
        key_text_start += 2
    else:
        key_text_start = key_data.find("\n\r\n")
        if key_text_start > 0:
            key_text_start += 3
    key_text_end = key_data.find("\n=")

    # validate the key data                                                                                               
    if not key_text_start or not key_text_end:
        raise ValidationError("PGP Key Data is invalid")
    # get the key text as a single string so we can validate the base64 encoding                                          
    key_text = key_data[key_text_start:key_text_end].replace("\n", "")
    key_text = key_text.replace("\r", "")
    # RE MAGIC                                                                                                            
    if not search("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", key_text):
        raise ValidationError("PGP Key Data is invalid")
    # if we got here, data is good!                                                                                       
    return key_data
        
class ContactPgPForm(forms.ModelForm):
    #pgp_key_data = forms.CharField(max_length=200,
    #                               required=False,
    #                               widget=forms.TextInput())
    def __init__(self, *args, **kwargs):
        super(ContactPgPForm, self).__init__(*args, **kwargs)
        self.fields['startdate'].required=False
        self.fields['enddate'].required=False
        self.fields['pgp_protocol'].required=False
        self.fields['version'].required=False
        self.fields['pgp_key_data'].required=False
        self.fields['pgp_key_id'].required=False
        

    def clean_pgp_key_id(self):
        key_id = self.cleaned_data['pgp_key_id']
        if key_id != '':
            if search("[^0-9a-fA-F]", key_id) is not None:
                raise ValidationError("PGP Key ID may contain only hexadecimal characters")
        return key_id

    def clean_startdate(self):
        startdate = self.cleaned_data['startdate']
        if startdate:
            startdate = startdate.replace('-', '')
        return startdate

    def clean_enddate(self):
        enddate = self.cleaned_data['enddate']
        if enddate:
            enddate = enddate.replace('-', '')
        return enddate

    def clean(self):
        check = [self.cleaned_data.get('pgp_key_data'), self.cleaned_data.get('pgp_key_id')]
        if any(check):
            if self.cleaned_data.get('pgp_key_id'):
                if not(self.cleaned_data.get('startdate') and self.cleaned_data.get('enddate')):
                    raise ValidationError('Dates are required if PGP Key not provided')
            return self.cleaned_data
        raise ValidationError('Either PGP Key or ID is required')
    
    def clean_pgp_key_data(self):
        key_data = self.cleaned_data['pgp_key_data']
        return pgp_validator(key_data)
    
    class Meta:
        model = ContactPgP
        fields = ['id', 'pgp_key_id', 'pgp_fingerprint', 'pgp_key_data', 'pgp_email', 'pgp_protocol', 'startdate', 'enddate', 'revoked', 'version']
        widgets = {'version':forms.HiddenInput(),
                   'pgp_key_data':forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),}


class AddEmailTemplateForm(forms.ModelForm):

    plain_text = forms.CharField(
        widget=forms.Textarea(),
	label=_('Email Body'),
	required=True,
        initial=settings.STANDARD_EMAIL_SIGNATURE)
    
    class Meta:
        model = EmailTemplate
        exclude = ('user', 'modified', 'locale', 'body_only', 'html', 'heading')

        
        
class AddCaseTemplateForm(forms.ModelForm):

    queue = forms.ChoiceField(
        widget=forms.Select(attrs={'class': 'form-control'}),
        choices=(),
        required=True,
        label=_('Ticket Queue'),
    )

    def __init__(self, *args, **kwargs):
        super(AddCaseTemplateForm, self).__init__(*args, **kwargs)
        self.fields['vendor_email'].required = False
        self.fields['participant_email'].required = False

    class Meta:
        model = CaseTemplate
        exclude = ('user', 'date_modified',)
        widgets = {'description':forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),}

    def clean_queue(self):
        data = self.cleaned_data['queue']
        if data in [None, '', 'None']:
            return self.ValidationError("must pick a queue")
        else:
            queue = TicketQueue.objects.get(id=int(data))
            return queue

class EditCaseTemplateTaskForm(forms.ModelForm):
    assigned_to = forms.ChoiceField(
        widget=forms.Select(attrs={'class': 'form-control'}),
        choices=(),
        required=False,
        label=_('Assign a User'),
    )

    def __init__(self, *args, **kwargs):
        super(EditCaseTemplateTaskForm, self).__init__(*args, **kwargs)
        self.fields['task_priority'].required = False
        self.fields['time_to_complete'].required = False
        assignable_users = User.objects.filter(is_active=True).order_by(User.USERNAME_FIELD)
        self.fields['assigned_to'].choices = [(None, '------')] + [(u.id, u.get_username()) for u in assignable_users]

    def clean_assigned_to(self):
        data = self.cleaned_data['assigned_to']
        if data in [None, '', 'None']:
            return None
        try:
            userassign = User.objects.get(id = int(data))
            return userassign
        except UserNotExist:
            return None
        
    class Meta:
        model = CaseTask
        fields = ["task_title", "task_description", "assigned_to", "task_priority", "dependency", "time_to_complete", "template"]
        widgets = {'description': forms.Textarea(attrs={'class': 'form-control'}),
                   'template': forms.HiddenInput()}
        
class AddCaseTemplateTaskForm(forms.ModelForm):

    assigned_to = forms.ChoiceField(
        widget=forms.Select(attrs={'class': 'form-control'}),
	choices=(),
        required=False,
        label=_('Assign a User'),
    )
    
    def __init__(self, *args, **kwargs):
        self.template = kwargs.pop("template")
        super(AddCaseTemplateTaskForm, self).__init__(*args, **kwargs)
        self.fields['task_priority'].required = False
        self.fields['time_to_complete'].required = False
        self.fields['template'].initial = self.template
        assignable_users = User.objects.filter(is_active=True).order_by(User.USERNAME_FIELD)
        self.fields['assigned_to'].choices = [(None, '------')] + [(u.id, u.get_username()) for u in assignable_users]
        
    class Meta:
        model = CaseTask
        fields = ["task_title", "task_description", "assigned_to", "task_priority", "dependency", "time_to_complete", "template"]
        widgets = {'description': forms.Textarea(attrs={'class': 'form-control'}),
        'template': forms.HiddenInput()}

        
    def clean_assigned_to(self):
        data = self.cleaned_data['assigned_to']
        if data in [None, '', 'None']:
            return None
        try:
            userassign = User.objects.get(id = int(data))
            return userassign
        except User.DoesNotExist:
            return None

class AddVulnerabilityForm(forms.ModelForm):
    """cve_allocator = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Produce JSON CVE file?',
	required=False,
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'}))

    ask_vendor_status = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Itemize in vendor record?',
        required=False,
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'}))
    """

    date_public = forms.DateTimeField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off'}),
        label=_('Date Public'),
        required=False
    )
    
    taggles = forms.CharField(
        max_length=300,
        label='Tag(s)',
        required=False)
    
    class Meta:
        model = Vulnerability
        fields = ['cve', 'description', 'taggles', 'date_public']
        widgets = {'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),}

    def __init__(self, *args, **kwargs):
        super(AddVulnerabilityForm, self).__init__(*args, **kwargs)
       # self.fields['cve_allocator'].initial = False
       # self.fields['ask_vendor_status'].initial=True

    def clean_cve(self):
        if self.cleaned_data['cve']:
            if self.cleaned_data['cve'].lower().startswith('cve-'):
                return self.cleaned_data['cve'][4:]
            return self.cleaned_data['cve']


class AddExploitForm(forms.ModelForm):

    reference_date = forms.DateTimeField(
        input_formats=['%Y-%m-%d'],
        widget=forms.DateInput(attrs={'placeholder':'YYYY-MM-DD', 'autocomplete':'off'}),
        required=False
    )
    
    class Meta:
        model=VulExploit
        fields = ('id', 'link', 'reference_type', 'reference_date', 'notes')
        widgets = {
            'id': forms.HiddenInput(),
            'reference_type': forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'})
        }
        
class AddCWEForm(forms.ModelForm):

    class Meta:
        model = VulCWE
        exclude = ('vul', 'user', 'date_added')
        widgets = {
            'id': forms.HiddenInput()
        }

class AddCVECWEForm(forms.Form):
    cwe = forms.CharField(
        max_length=500,
        required=True
    )
    def clean_cwe(self):
        if self.cleaned_data['cwe']:
            if self.cleaned_data['cwe'].lower().startswith('cwe-'):
                return self.cleaned_data['cwe']
            else:
                raise forms.ValidationError("Invalid CWE selection, must start with CWE-")
        return


class CVEServicesForm(forms.ModelForm):

    class Meta:
        model = CVEServicesAccount
        fields = ('team', 'org_name', 'api_key', 'email', 'first_name', 'last_name', 'active')
    
class CVEAllocationForm(forms.ModelForm):
    vul = forms.IntegerField(
        required=False,
	widget=forms.HiddenInput()
    )

    date_public = forms.DateTimeField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off'}),
	label=_('Date Public'),
        required=True
    )

    class Meta:
        model = CVEAllocation
        exclude = ('references', 'work_around', 'cwe', 'user', 'search_vector', 'source', 'resolution', 'credit')
        widgets = {'description': forms.Textarea(attrs={'class':'form-control'}),
                   'resolution': forms.Textarea(attrs={'class':'form-control'}),
                   'cve_name': forms.TextInput(attrs={'placeholder':'CVE-yyyy-nnnn'})}

    def clean_vul(self):
        data = self.cleaned_data['vul']
        if data in [None, '', 'None']:
            return None
        else:
            vul = Vulnerability.objects.get(id=int(data))
            return vul

    def clean_cve_name(self):
        if self.cleaned_data['cve_name']:
            if self.cleaned_data['cve_name'].lower().startswith('cve-'):
                return self.cleaned_data['cve_name']
            else:
                raise forms.ValidationError("Invalid CVE identifier, must start with CVE-")
            

class CVEAffectedProductForm(forms.ModelForm):

    version_affected = forms.ChoiceField(
        widget = forms.Select(attrs={'class': 'form-control'}),
        label=_('Version Affected'),
        required=False,
        choices=([('None', None), ('<', '< (affects X versions prior to n)'), ('<=', '<= (affects X versions up to n)'), ('=', '= (affects n)'), ('>', '> (affects X versions above n)'), ('>=', '>= (affects X versions n and above)')])
        )
    
    class Meta:
        model = CVEAffectedProduct
        exclude = ('cve',)
        

class CVEReferencesForm(forms.Form):

    ref_source = forms.ChoiceField(
	widget = forms.Select(attrs={'class': 'form-control'}),
        label=_('Reference Source'),
	required=True,
        choices=([('URL', 'URL'),('CERT-VN', 'CERT-VN'), ('MISC', 'MISC'), ('CONFIRM', 'CONFIRM')])
     )
    
    reference = forms.URLField(
	label=_('Reference'),
        widget = forms.TextInput(attrs={'placeholder': 'e.g., https://dhs.gov.'}),
        help_text = 'Please provide reference URL.',
        max_length=500
    )

class CVEWorkaroundForm(forms.Form):
    workaround = forms.CharField(
        max_length=1000,
        label='Describe workaround')

class VendorVulStatementForm(forms.Form):
    statement = forms.CharField(
	widget = forms.Textarea(),
        label=_('Statement'),
	help_text=_('Provide a general statement for all vulnerabilities in this case.'),
	required=False
    )

    references = forms.CharField(
        widget = forms.Textarea(),
        label=_('References'),
	help_text=_('Provide references for all vulnerabilities in this case. 1 URL per line.'),
        required=False
    )
    
class StatementForm(forms.Form):
    share = forms.BooleanField(
        label=_('Share status and statement pre-publication'),
        help_text=('Checking this box will share your status and statement with all'
                   ' vendors and participants in this case before the vulnerability note is published.'),
        required=False)
    
    statement = forms.CharField(
        widget = forms.Textarea(),
        label=_('Statement'),
        help_text=_('Provide a general statement for all vulnerabilities in this case.'),
        required=False
    )

    references = forms.CharField(
        widget = forms.Textarea(),
        label=_('References'),
        help_text=_('Provide references for all vulnerabilities in this case. 1 URL per line.'),
        required=False
    )

    addendum = forms.CharField(
        widget = forms.Textarea(),
        label=_('Coordinator Addendum'),
        help_text=_('Text added by the coordination team.'),
        required=False
    )

    statement_date = forms.DateField(
        input_formats=['%Y-%m-%d'],
        widget=forms.DateInput(attrs={'placeholder':'YYYY-MM-DD', 'autocomplete':'off'}),
        required=False,
        label=_('Statement Date'),
        help_text=_('The date the vendor provided their statement.'),
    )

class AddUserToContactForm(forms.Form):

    contact = forms.CharField(
        required=False)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super(AddUserToContactForm, self).__init__(*args, **kwargs)


class CreateNewVinceUser(forms.Form):
    send_email = forms.BooleanField(
        help_text=_('Send an email to this user with their temporary PLAINTEXT password'),
        label = "Send email?",
        required=False)

    email = forms.CharField(
        max_length=254,
        required=True,
        help_text=_('This will be the login username. Please note that this field is CASE SENSITIVE.'),
        label="Email address")
    
    preferred_username=forms.RegexField(label=_("Preferred Display Name"), max_length=254, help_text=_('The name visible to other VINCE users. It may only contain 1 space and may not contain certain special characters. (The user can modify this later)'), regex=r'^[\w\+-_]+(\s[\w\+-_]+)*$', required=True,
                                            error_messages={'invalid':_("Invalid username. The display name may only contain 1 space and may not contain certain special characters.")})

    password1 = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.PasswordInput,
        label="New Password",
        help_text=_('Password Requirements:<ul>\
        <li>Minimum length is 8 characters</li>\
        <li>Maximum length is 50 characters</li>\
        <li>Requires at least 1 number</li>\
        <li>Requires at least 1 special character ("+" and "=" don\'t count)</li>\
        <li>Requires uppercase letters</li>\
        <li>Requires lowercase letters</li>\
        </ul>'))

    password2 = forms.CharField(
        max_length=50,
        required=True,
        widget=forms.PasswordInput,
        label="Re-type Password")

    def __init__(self, *args, **kwargs):
        super(CreateNewVinceUser, self).__init__(*args, **kwargs)
        self.fields['send_email'].initial = False

    def clean_email(self):
        # lowercase the domain part of the email address
        # because django is going to do it anyway when creating
        # the user and we need django and cognito to be in sync
        email = self.cleaned_data['email']
        parts = email.strip().split('@', 1)
        if len(parts) > 1:
            parts[1] = parts[1].lower()
        email = '@'.join(parts)
        return email

class NewEmailAll(forms.ModelForm):

    to_group = forms.ChoiceField(
        widget = forms.Select(attrs={'class': 'form-control'}),
        label=_('To:'),
        required=True,
        choices=([(1, 'All VINCE Vendor Users'), (2, 'All Admins'), (3, 'All Users'), (4, 'All Staff'), (5, 'Vendors without Users')])
    )
    
    subject = forms.CharField(
        max_length=200,
        help_text=_('The subject of the email. If related to a case or ticket, Case ID or Ticket ID will be prepended to subject.'),
    )

    email_body = forms.CharField(
        widget=forms.Textarea(),
        label=_('Email Body'),
        required=True,
        initial=settings.STANDARD_EMAIL_SIGNATURE)

    ticket = forms.CharField(
        max_length=200,
        label=_('Ticket ID'),
        required=False)

    case = forms.CharField(
        max_length=200,
        label=_(f'Is this related to a case? [{settings.CASE_IDENTIFIER}nnnnnn]'),
        required=False)

    class Meta:
        model = VinceEmail
        fields = ('to_group', 'subject', 'email_body', 'ticket', 'case')
    

    def clean_case(self):
        data = self.cleaned_data['case']
        if data in [None, '', 'None']:
            return
        else:
            if data.startswith(settings.CASE_IDENTIFIER):
                data = data[len(settings.CASE_IDENTIFIER):]
            try:
                case = VulnerabilityCase.objects.get(vuid=data)
                return case
            except:
                raise forms.ValidationError("Invalid Case Selection")

    def clean_ticket(self):
        data = self.cleaned_data['ticket']
        if data in [None, '', 'None']:
            return
        try:
            ticket = Ticket.objects.get(id=data)
            return ticket
        except:
            raise forms.ValidationError("Invalid Ticket Selection. Use only numeric ID of Ticket.")

    def save(self, user, commit=True):

        if self.cleaned_data['to_group'] == '1':
            to = "All VINCE Vendor Users"
        elif self.cleaned_data['to_group'] == '2':
            to = "All Admins"
        elif self.cleaned_data['to_group'] == '3':
            to = "All Users"
        elif self.cleaned_data['to_group'] == '4':
            to = "All Staff"
        else:
            to = "All Vendors without users"

        case = self.cleaned_data['case']
        if case:
            queue = get_user_case_queue(user)
        else:
            queue = get_user_gen_queue(user)

        if self.cleaned_data['ticket']:
            tkt = self.cleaned_data['ticket']
            #add followup with email content
            fup = FollowUp(ticket=tkt,
                           title=f"Sending broadcast email with subject [{tkt.queue.slug}-{tkt.id}] {self.cleaned_data['subject']}",
                           user=user,
                           comment=self.cleaned_data['email_body'])
            fup.save()
        else:
            tkt = Ticket(title = f"New Email to {to}",
                         created = timezone.now(),
                         status = Ticket.CLOSED_STATUS,
                         queue = queue,
                         description = self.cleaned_data['email_body'],
                         submitter_email = user.email,
                         assigned_to = user)
            if case:
                tkt.case = case
            
            tkt.save()
        
        subject = f"[{tkt.queue.slug}-{tkt.id}] {self.cleaned_data['subject']}"

        notification = VendorNotificationEmail(subject=self.cleaned_data['subject'], email_body = self.cleaned_data['email_body'])
        notification.save()
            
        email = VinceEmail(user=user,
                           to=to,
                           ticket=tkt,
                           notification=notification)
        email.save()

        
        send_worker_email_all(self.cleaned_data['to_group'], subject, self.cleaned_data['email_body'], tkt.id, user)
        
        return 
        
class NewVinceEmail(forms.ModelForm):

    subject = forms.CharField(
        max_length=200,
        help_text=_('The subject of the email. If related to a case or ticket, Case ID or Ticket ID will be prepended to subject.'),
    )

    email_template = forms.ChoiceField(
        choices=(),
        label="Choose an email template",
	required=False)
    
    email_body = forms.CharField(
	widget=forms.Textarea(),
	label=_('Email Body'),
	required=True,
        initial=settings.STANDARD_EMAIL_SIGNATURE)

    contact = forms.CharField(
        max_length=250,
        label=_('Contact'),
        required=False,
        help_text=_('Auto-add emails by choosing Contact')
    )

    #certificate = forms.CharField(
    #    max_length=250,
    #    label=_('Choose a previously uploaded certificate'),
    #    required=False)

    new_certificate = forms.FileField(
        required=False,
        label=_('Upload New X.509 Certificate (.pem)'),
	widget=forms.FileInput(attrs={'class':'vulupload'})
    )

    pgp_key = forms.CharField(
        widget=forms.Textarea(),
        required=False,
        label=_('Full PGP Key'))

    ticket = forms.CharField(
        max_length=200,
        label=_('Ticket ID'),
        required=False)

    case = forms.CharField(
        max_length=200,
        label=_(f'Is this related to a case? [{settings.CASE_IDENTIFIER}nnnnnn]'),
        required=False)

    class Meta:
        model = VinceEmail
        fields = ('email_type', 'contact', 'to', 'email_template', 'subject', 'email_body', 'subject', 'ticket', 'case', 'new_certificate', 'certificate', 'pgp_key', 'pgp_key_id')


    def __init__(self, *args, **kwargs):
        super(NewVinceEmail, self).__init__(*args, **kwargs)
        self.fields['certificate'].required = False
        self.fields['certificate'].label = "Or select a previously uploaded certificate"

    
    def clean_case(self):
        data = self.cleaned_data['case']
        if data in [None, '', 'None']:
            return
        else:
            if data.startswith(settings.CASE_IDENTIFIER):
                data = data[len(settings.CASE_IDENTIFIER):]
            try:
                case = VulnerabilityCase.objects.get(vuid=data)
                return case
            except:
                raise forms.ValidationError("Invalid Case Selection")

    def clean_pgp_key_data(self):
        key_data = self.cleaned_data['pgp_key_data']
        return pgp_validator(key_data)

    def clean_ticket(self):
        data = self.cleaned_data['ticket']
        if data in [None, '', 'None']:
            return
        try:
            ticket = Ticket.objects.get(id=data)
            return ticket
        except:
            raise forms.ValidationError("Invalid Ticket Selection. Use only numeric ID of Ticket.")

class EmailFilterForm(forms.Form):
    wordSearch = forms.CharField(
        max_length=100,
	label='Keyword(s)',
        widget=forms.TextInput(attrs={'placeholder':'Keyword search'}),
        required=False)
    
    page = forms.CharField(max_length=5,
                           required=False)

    method = forms.MultipleChoiceField(
        choices=VinceEmail.EMAIL_TYPE,
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'})
    )
    
    datestart = forms.DateField(required=False)
    
    dateend = forms.DateField(required=False)
    
    user = forms.MultipleChoiceField(
        choices=(),
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}))

    def __init__(self, *args, **kwargs):
        super(EmailFilterForm, self).__init__(*args, **kwargs)
        self.fields['dateend'].initial = timezone.now

class EmailImportForm(forms.Form):
    email_key = forms.CharField(max_length=200, label="Object Key", required=True)

class UserSearchForm(forms.Form):
    email = forms.CharField(max_length=300, label="Email", required=True)

    
class CognitoUserProfile(forms.Form):
    first_name = forms.CharField(
        max_length=200,
        required=False,
        disabled=True,
    )
    last_name = forms.CharField(
        max_length=200,
        required=False,
        disabled=True,
    )
    country = CountryField(default='US').formfield(
        disabled=True,
        required=False)

    phone_number = forms.CharField(
        widget=forms.TextInput(),
        disabled=True,
        required=False,
        max_length=60)
    
    email = forms.EmailField(
        required=True,
        label="Login Username/Email. This field is case sensitive."
    )
    preferred_username=forms.RegexField(
        label=_("Preferred Display Name"),
        max_length=254,
        help_text=_('The name displayed to other VINCE users. It may only contain 1 space and may not contain certain special characters.'),
        regex=r'^[\w\+-_]+(\s[\w\+-_]+)*$',
        required=True,
        error_messages={'invalid':_("Invalid username. Your display name may only contain 1 space and may not contain certain special characters.")})
    
    org = forms.CharField(
        max_length=200,
        label="Company/Affiliation",
        required=False,
        disabled=True)

    title = forms.CharField(
        max_length=200,
        label="Job Title",
        help_text=_('This field is visible to other VINCE users'),
        required=False,
        disabled=True)

class CalendarEventForm(forms.ModelForm):
    
    class Meta:
        model = CalendarEvent
        fields = ('user', 'event_id', 'date')
        widgets = {
            'date': forms.HiddenInput()
        }


class AddRoleUserForm(forms.ModelForm):

    weight = forms.IntegerField(
        max_value=5,
        min_value=1)
    
    class Meta:
        model = UserAssignmentWeight
        fields = ('user', 'role', 'weight')
        widgets = {
            'role': forms.HiddenInput()
        }

class AutoAssignForm(forms.Form):

    role = forms.ChoiceField(
        choices=(),
        label='Which role would you like to assign to this ticket?',
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet'}),
        required=True)

class AddNewTagForm(forms.ModelForm):

    alert_on_add = forms.ChoiceField(
	choices=[(True, 'Yes'), (False, 'No')],
        help_text='Do you want to be alerted when adding a contact with this tag to a case?',
        label='Alert on add?',
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'}),
	required=False)

    class Meta:
        model = TagManager
        fields = ('tag', 'description', 'alert_on_add', 'tag_type')
        widgets = {
            'tag_type': forms.HiddenInput(),
        }

    def __init__(self, *args, **kwargs):
        super(AddNewTagForm, self).__init__(*args, **kwargs)
        self.initial['alert_on_add'] = False

    def clean_tag(self):
        return self.cleaned_data['tag'].lower()
    
    
class ReminderForm(forms.ModelForm):

    case = forms.CharField(
        required=False,
        label="Related to Case?",
        widget=forms.TextInput(attrs={'placeholder':settings.CASE_IDENTIFIER}),
    )

    ticket = forms.CharField(
        required=False,
        label="Related to Ticket?",
        widget=forms.TextInput(attrs={'placeholder':'Ticket ID e.g. gen-123'}),
    )
    
    user = forms.ChoiceField(
        widget=forms.Select(attrs={'class': 'form-control'}),
        choices=(),
        label=_('Remind User'),
    )

    alert_date = forms.DateTimeField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off'}),
        label=_('Alert Date'),
    )

    create_ticket = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Create a new ticket on the alert date?',
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'}),
	required=False)
    
    class Meta:
        model = VinceReminder
        fields = ('alert_date', 'title', 'case', 'ticket', 'user', 'create_ticket', 'frequency')


    def __init__(self, *args, **kwargs):
        super(ReminderForm, self).__init__(*args, **kwargs)
        self.initial['create_ticket'] = False
        
    def clean_case(self):
        data = self.cleaned_data['case']
        if data in [None, '', 'None']:
            return
        else:
            if data.startswith(settings.CASE_IDENTIFIER):
                data = data[len(settings.CASE_IDENTIFIER):]
            try:
                case = VulnerabilityCase.objects.get(vuid=data)
                return case
            except:
                raise forms.ValidationError("Invalid Case Selection")

    def clean_ticket(self):
        data = self.cleaned_data['ticket']
        if data in [None, '', 'None']:
            return
        else:
            if not(isinstance(data, int)):
                queues = list(TicketQueue.objects.all().values_list('slug', flat=True))
                queues.append("General")
                rq= '|'.join(queues)
                rq = "(?i)(" + rq + ")-(\d+)"
                m = re.search(rq, data)
                if m:
                    data = m.group(2)
                else:
                    raise forms.ValidationError("Invalid Ticket Selection. Use either numeric ticket id or slug-id.")    
                    
            try:
                ticket = Ticket.objects.get(id=data)
                return ticket
            except:
                raise forms.ValidationError("Invalid Ticket Selection. Use either numeric ticket id or slug-id.")

    def clean_user(self):
        data = self.cleaned_data['user']
        try:
            
            return User.objects.get(id=data)
        except:
            raise form.ValidationError("Invalid User Selection")
        


class CVEReserveForm(forms.Form):

    account = forms.ChoiceField(
        choices=(),
        widget=forms.Select(attrs={'class': 'form-control'}),
        required=False,
        label=_('Account'),
    )

    year = forms.ChoiceField(
        choices=(),
        widget = forms.Select(attrs={'class': 'form-control'}),
        required=True,
        label=_('Year')
    )

    count = forms.IntegerField(
        required=False,
        label=_("Count"),
        max_value=10,
        min_value=1
    )
    
    sequential = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label=_('Reserve Sequential IDs'),
        required=False,
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'})
    )

    def __init__(self, *args, **kwargs):
        super(CVEReserveForm, self).__init__(*args, **kwargs)
        self.fields['sequential'].initial = False
        

class CVEFilterForm(forms.Form):
    wordSearch = forms.CharField(
        max_length=100,
	label='Keyword(s)',
        widget=forms.TextInput(attrs={'placeholder':'CVE ID search'}),
        required=False)

    year = forms.CharField(
        max_length=5,
        label="Year",
        widget=forms.TextInput(attrs={'placeholder':'Year'}),
        required=False)

    vince = forms.BooleanField(
        required=False,
        label="Search VINCE CVEs")
        
    
