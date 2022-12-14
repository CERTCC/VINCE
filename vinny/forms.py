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
from django import forms
from django.contrib.auth.models import User, Group
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm
from django.utils.translation import gettext, gettext_lazy as _, pgettext_lazy
from django.utils import timezone
from vinny.models import *
from django.conf import settings
from vinny.lib import vince_comm_send_sqs, new_track_ticket, send_comm_worker_msg_all
from vinny.permissions import group_case
from datetime import date
from re import search
from django.core.exceptions import ValidationError
import mimetypes
import os
from django.utils.encoding import smart_text
from vinny.settings import DEFAULT_USER_SETTINGS

class SignUpForm(UserCreationForm):
    organization = forms.CharField(
        max_length=200,
        label="Company/Affiliation",
        required=False)
    email = forms.CharField(
        max_length=254,
        required=True,
        label="Email address")
    preferred_username = forms.CharField(
        max_length=254,
        required=True,
        label="Preferred Username",
        help_text=_('The username visible to other VINCE users'),)

    class Meta:
        model = User
        fields = ("email", "first_name", "last_name", "organization", "preferred_username", "password1", "password2")


class PostForm(forms.Form):
    content = forms.CharField(
        widget=forms.Textarea(),
        label=_('Reply'),
        required=False
    )


class EditPostForm(forms.Form):
    post = forms.CharField(
        widget=forms.Textarea(),
        label=_('Edit Post'),
        required=False
    )

WHY_CHOICES = [(1, "General Question"),
               (9, "Question about a Vulnerability Report"),
               (2, "Question about a Case"),
               (10, "Join my organization's VINCE Group"),
               (3, "New Vendor Request"),
               (4, "Request Group Admin Privileges"),
               (5, "Request for Vendor Access to a Case"),
               (6, "User Access Question"),
               (7, "VINCE Help"),
               (8, "Provide feedback")]



class UserModelChoiceField(forms.ModelChoiceField):

    def label_from_instance(self, obj):
        return get_user_model().objects.exclude(id=obj.id)

class SendMessageAllForm(forms.ModelForm):

    from_group = forms.ChoiceField(
        widget = forms.Select(attrs={'class': 'form-control'}),
        label=_('From Group:'),
        required=True,
        choices=()
    )
    
    subject = forms.CharField(
	required = True,
        label=_('Subject'),
    )

    to_group = forms.ChoiceField(
        widget = forms.Select(attrs={'class': 'form-control'}),
        label=_('To:'),
        required=True,
        choices=([(1, 'All Vendors'), (2, 'All Admins'), (3, 'All Users'), (4, 'All Staff')])
    )

    content = forms.CharField(
        widget = forms.Textarea(),
        label=_('Content'),
        required=False,
    )

    class Meta:
        model = Message
        fields = ["from_group", "to_group", "subject", "content"]


    def __init__(self, *args, **kwargs):
        """ 
        Add any custom fields that are defined to the form.
        """
        super(SendMessageAllForm, self).__init__(*args, **kwargs)
        if self.initial.get("from_group") is not None:
            self.fields["from_group"].choices = self.initial.get("from_group")
        
    def save(self, user, commit=True):

        send_comm_worker_msg_all(self.cleaned_data['to_group'], self.cleaned_data['subject'], self.cleaned_data['content'], user, self.cleaned_data['from_group'])

        return

class SendMessageUserForm(forms.ModelForm):

    subject = forms.CharField(
        required = True,
        label=_('Subject'),
    )

    case = forms.ChoiceField(
        widget = forms.Select(attrs={'class': 'form-control'}),
        label=_('Case'),
        required=False,
        choices=()
    )

    to_user = forms.MultipleChoiceField(
        widget = forms.Select(attrs={'class': 'form-control'}),
        label=_('To user'),
        required=False,
        choices=(),
        help_text=_('Tag user by email to send a message')
    )

    to_group = forms.MultipleChoiceField(
        widget = forms.Select(attrs={'class': 'form-control'}),
        label=_('To organization'),
        required=False,
        choices=(),
        help_text=_('Tag organization by name. Selecting an organization will send a message to all users in the group')
    )

    content = forms.CharField(
        widget = forms.Textarea(),
        label=_('Content'),
        required=False,
    )

    attachment = forms.FileField(
        required=False,
        label=_('Attach File'),
        help_text=_('You can attach a file such as a document or screenshot to this message.'),
        widget=forms.FileInput(attrs={'class':'vulupload'})
    )


    def get_user_choices(self, user):
        return [(0, '--------')] + [(q.id, q.username) for q in get_user_model().objects.exclude(id=user.id)]

    def get_group_choices(self):
        return [(0, '--------')] + [(q.id , q.groupcontact.contact.vendor_name) for q in Group.objects.all().exclude(groupcontact__isnull=True)]

    class Meta:
        model = Message
        fields = ["subject", "to_user", "to_group", "case", "content", "attachment"]

    def __init__(self, *args, **kwargs):
        """
        Add any custom fields that are defined to the form.
        """
        self.user = kwargs.pop("user")
        self.privgroupchat = kwargs.pop("privgroupchat")
        super(SendMessageUserForm, self).__init__(*args, **kwargs)
        if self.initial.get("to_user") is not None:
            self.fields["to_user"].choices = [(q.id, q.username) for q in get_user_model().objects.filter(pk=self.initial["to_user"])]
            self.fields["to_group"].widget = forms.HiddenInput()
        elif self.initial.get("to_group") is not None:
            self.fields["to_group"].choices = [(q.id, q.groupcontact.contact.vendor_name) for q in Group.objects.filter(groupcontact__contact__vendor_id=self.initial["to_group"])]
            self.fields["to_user"].widget = forms.HiddenInput()
        else:
            self.fields["to_user"].choices = self.get_user_choices(self.user)
            self.fields["to_group"].choices = self.get_group_choices()
        if self.initial.get("case") is not None:
            self.fields["case"].choices = self.initial.get("case")
            if self.initial.get("select_case") is not None:
                logger.debug(" GOT A SELECT CASE")
                self.fields["case"].initial = self.initial.get("select_case")
        if self.privgroupchat:
            self.fields['to_user'].widget = forms.HiddenInput()


    def save(self, files=None, commit=True):

        logger.debug("IN SAVE sendmsguserform")
        data = self.cleaned_data

        to_list = []
        to_list_str = []
        group = None
        if data['to_user']:
            to_list = list(get_user_model().objects.filter(email__in=data['to_user']).values_list('id', flat=True))
            to_list_str = list(get_user_model().objects.filter(email__in=data['to_user']).values_list('email', flat=True))
        if data['to_group']:
            contacts = VinceCommContact.objects.filter(vendor_name__in=data['to_group']).values_list('groupcontact__group__id', flat=True)
            g_users = get_user_model().objects.filter(groups__id__in=contacts).values_list('id', flat=True)
            for x in g_users:
                if x not in to_list:
                    to_list.append(x)
            logger.debug(to_list)

            to_list_str.extend(list(Group.objects.filter(id__in=contacts).values_list('groupcontact__contact__vendor_name', flat=True).distinct()))
            logger.debug(to_list_str)
            group = contacts

        msg = Message.new_message(self.user, to_list, data['case'], data['subject'], data['content'])

        if group:
            msg.thread.to_group = (", ").join(list(Group.objects.filter(id__in=contacts).values_list('groupcontact__contact__vendor_name', flat=True).distinct()))

        # get from group from user group
        team = self.user.groups.filter(groupcontact__vincetrack=True).first()
        teamname=""
        if team:
            msg.thread.from_group = team.groupcontact.contact.vendor_name
            teamname = team.groupcontact.contact.vendor_name
        

        msg.thread.save()

        if files:
            for file in files:
                attachment = MessageAttachment.attach_file(msg, file)

        if data['case']:
            case = Case.objects.filter(id=data["case"]).first()
        else:
            case = None

        to_list_str = (", ").join(to_list_str)
        new_track_ticket("Inbox", f"Direct Message from {teamname} ({self.user.vinceprofile.vince_username}) to {to_list_str}: '{data['subject']}'", msg.id, case, self.user.username)

        return msg

class SendMessageForm(forms.ModelForm):

    subject = forms.ChoiceField(
        widget = forms.Select(attrs={'class': 'form-control'}),
        required = True,
        label=_('Why are you contacting us?'),
        choices=WHY_CHOICES,
    )

    case = forms.ChoiceField(
        widget = forms.Select(attrs={'class': 'form-control'}),
        label=_('Case'),
        required=False,
        choices=()
    )

    #org = forms.ChoiceField(
    #choices=[(True, 'Yes'), (False, 'No')],
    #label="Do you want to include other VINCE users in your organization?",
    #required=True,
    #widget=forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'}))

    vendor = forms.CharField(
        label=_('Vendor Name'),
        max_length=300,
        required = False)
    
    report = forms.ChoiceField(
        widget = forms.Select(attrs={'class': 'form-control'}),
        label=_('Vulnerability Report'),
        required=False,
        choices=()
    )

    #new_group_admin = forms.ChoiceField(
    #    widget = forms.Select(attrs={'class': 'form-control'}),
    #    label=_('Select new group administrator from the list'),
    #    required=False,
    #    choices=()
    #)

    content = forms.CharField(
        widget = forms.Textarea(),
        label=_('Content'),
        required=False
    )

    attachment = forms.FileField(
	required=False,
	label=_('Attach File'),
        help_text=_('You can attach a file such as a document or screenshot to this message.'),
        widget=forms.FileInput(attrs={'class':'vulupload'})
    )

    class Meta:
        model = Message
        fields = ["subject", "case", "report", "vendor", "content", "attachment"]

    def __init__(self, *args, **kwargs):
        """
        Add any custom fields that are defined to the form.
        """
        self.user = kwargs.pop("user")
        super(SendMessageForm, self).__init__(*args, **kwargs)
        #self.fields['org'].initial = False
        if self.initial.get("case") is not None:
            self.fields["case"].choices = self.initial.get("case")
            if self.initial.get("select_case") is not None:
                logger.debug(self.initial.get("select_case"))

                self.initial["case"] = self.initial.get("select_case")
        if self.initial.get("report") is not None:
            self.fields["report"].choices = self.initial.get("report")
        #self.fields["new_group_admin"].choices = self.initial.get("group_admin")
        self.fields["subject"].initial = self.initial.get("subject")

    def save(self, files=None, commit=True):
        data = self.cleaned_data

        cr = None
        why_choices = dict(WHY_CHOICES)
        why = int(data['subject'])
        if why == 4:
            #user = User.objects.filter(id=int(data['new_group_admin'])).first()
            subject = "Request Group Admin Change"
            data['case'] = None
        elif why == 2 and data['case']:
            vc = Case.objects.filter(id=data['case']).first()
            if vc:
                subject = "Question about Case " + vc.get_title()
        elif why == 9 and data['report']:
            cr = VTCaseRequest.objects.filter(id=data['report']).first()
            if cr:
                subject = "Question about Vulnerability Report " + cr.get_title()
        elif why == 10:
            data['case'] = None
            data['report'] = None
            if data['vendor']:
                subject = f"{self.user.username} requests access to Vendor Group: {data['vendor']}"
            else:
                subject = f"{self.user.username} requests access to Vendor Group"
        else:
            data['case'] = None
            data['report'] = None
            subject = why_choices[int(data['subject'])]


        #get a list of all cert/cc users:
        #to_users = list(User.objects.filter(groups__name='CERT/CC').values_list('id', flat=True))
        #print(to_users)
        msg = Message.new_message(self.user, [], data['case'], subject, data['content'])

        if files:
            for file in files:
                attachment = MessageAttachment.attach_file(msg, file)

        if why == 2 and data["case"]:
            case = Case.objects.filter(id=data["case"]).first()
            if case:
                subject = "Case Question from " + self.user.username
                new_track_ticket("Case", subject, msg.id, case, self.user.username)
                #create_ticket(None, subject, data['content'], self.user.username, vuid=case.vuid, msg=msg.id)
                return msg
        elif why == 9 and data["report"]:
            if cr:
                crfup = CRFollowUp(cr = cr,
                                   title = "sent message about report",
                                   user = self.user,
                                   comment = data['content'])
                crfup.save()
                vince_comm_send_sqs("CRUpdate", "Ticket", cr.vrf_id,
                                    self.user.username, None, "New Comment on CR")
                return msg
        elif why == 10:
            new_track_ticket("Vendor", subject, msg.id, None, self.user.username)
            return msg
        
        #ticket = create_ticket("Inbox", subject, data['content'], self.user.username, msg=msg.id)
        new_track_ticket("Inbox", subject, msg.id, None, self.user.username)

        return msg

class MessageReplyForm(forms.ModelForm):

    content = forms.CharField(
        widget=forms.Textarea(attrs={'placeholder': 'Type your reply here.'}),
        label=_('Reply'),
        required=False)

    attachment = forms.FileField(
        required=False,
        label=_('Attach File'),
        help_text=_('You can attach a file such as a document or screenshot to this message.'),
        widget=forms.FileInput(attrs={'class':'vulupload'})
    )

    def __init__(self, *args, **kwargs):
        self.thread = kwargs.pop("thread")
        self.user = kwargs.pop("user")
        super(MessageReplyForm, self).__init__(*args, **kwargs)

    def save(self, files=None, commit=True):
        msg = Message.new_reply(
            self.thread, self.user, self.cleaned_data["content"]
        )
        if files:
            for file in files:
                attachment = MessageAttachment.attach_file(msg, file)

        if msg.thread.case:
            #if self.user.groups.filter(name='vincetrack').exists():
            #    group = "CERT/CC"
            #else:
            group = group_case(self.user, msg.thread.case)
            vince_comm_send_sqs("MessageReply", "Case", msg.thread.case.vuid, self.user.username, group, "Reply to Thread from " + self.user.username, "Inbox", msg.id)
#            ca = create_case_action(msg.thread.case.vuid, self.user.username, "Reply to Thread from " + self.user.username, self.cleaned_data["content"], msg=msg)
#            if ca:
            return msg

#        ticket = update_ticket("Inbox", self.user.email, self.cleaned_data["content"], msg.id)
        new_track_ticket("Inbox", "Message Reply", msg.id, None, self.user.username)

        return msg

    class Meta:
        model = Message
        fields = ["content", "attachment"]


class UploadLogoForm(forms.ModelForm):
    logo = forms.FileField(
        required=False,
        label=_('Upload logo'),
        widget=forms.FileInput(attrs={'class':'vulupload'})
    )

    def __init__(self, *args, **kwargs):
        self.contact = kwargs.pop("contact")
        self.user = kwargs.pop("user")
        super(UploadLogoForm, self).__init__(*args, **kwargs)

    def save(self, file=None, commit=True):
        if file:
            gc = GroupContact.objects.filter(contact=self.contact).first()
            gc.logo = file
            gc.save()
        else:
            # this is a delete
            gc = GroupContact.objects.filter(contact=self.contact).first()
            gc.logo = None
            gc.save()
        return gc


    class Meta:
        model = GroupContact
        fields = ['logo']

class AddTrackingForm(forms.ModelForm):

    tracking = forms.CharField(
        required=False,
        label=_('Tracking Number'))

    def __init__(self, *args, **kwargs):
        self.case = kwargs.pop("case")
        self.group = kwargs.pop("group")
        self.user = kwargs.pop("user")
        super(AddTrackingForm, self).__init__(*args, **kwargs)

    def save(self, commit=True):

        if self.instance:
            self.instance.tracking= self.cleaned_data['tracking']
            self.instance.case=self.case
            self.instance.group=self.group
            self.instance.added_by=self.user
            self.instance.save()
            return self.instance
        else:
            tracking = CaseTracking(case=self.case,
                                    tracking=self.cleaned_data['tracking'],
                                    group = self.group,
                                    added_by = self.user)
            tracking.save()
            return tracking



    class Meta:
        model=CaseTracking
        fields = ['tracking']


class UploadDocumentForm(forms.ModelForm):

    attachment = forms.FileField(
        required=True,
        label=_('Attach File'),
        widget=forms.FileInput(attrs={'class':'vulupload'})
    )

    def __init__(self, *args, **kwargs):
        self.case = kwargs.pop("case")
        self.user = kwargs.pop("user")
        super(UploadDocumentForm, self).__init__(*args, **kwargs)


    def save(self, commit=True):
        action = VendorAction(title="User uploaded document",
                              user=self.user,
                              case=self.case)
        action.save()

        file = self.cleaned_data['attachment']

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
            att.save()

        new_attachment = VinceCommCaseAttachment(file = att,
                                                 action=action)
        new_attachment.save()

        return new_attachment

    class Meta:
        model=VinceCommCaseAttachment
        fields = ['attachment']


class UploadFileForm(forms.ModelForm):

    attachment = forms.FileField(
	required=True,
        label=_('Attach File'),
        widget=forms.FileInput(attrs={'class':'vulupload'})
    )

    def __init__(self, *args, **kwargs):
        self.report = kwargs.pop("report")
        self.user = kwargs.pop("user")
        super(UploadFileForm, self).__init__(*args, **kwargs)


    def save(self, commit=True):
        comment = f"{self.cleaned_data['attachment'].name}"
        action = CRFollowUp(title="uploaded document",
                            user=self.user,
                            comment=comment,
                            cr=self.report)
        action.save()

        file = self.cleaned_data['attachment']

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
            att.save()


        new_attachment = ReportAttachment(file = att,
                                          action=action)
        new_attachment.save()

        return new_attachment

    class Meta:
        model= ReportAttachment
        fields = ['attachment']

class VulStatementForm(forms.Form):
    statement = forms.CharField(
        widget = forms.Textarea(),
        label=_('Statement'),
        help_text=_('Provide a statement for this specific vulnerability.'),
        required=False
    )

    references = forms.CharField(
	widget = forms.Textarea(),
        label=_('References'),
	help_text=_('Provide references (URLs) for this specific vulnerability. 1 URL per line.'),
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
        label=_('Case Statement'),
        help_text=_('Provide a general statement for all vulnerabilities in this case. This statement will be published verbatim in our vulnerability note.'),
        required=False
    )

    references = forms.CharField(
        widget = forms.Textarea(),
        label=_('Case References'),
        help_text=_('Provide references (URLs) for all vulnerabilities in this case. 1 URL per line. We will provide the list of references with your statement in our published vulnerability note.'),
        required=False
    )

    addendum = forms.CharField(
        disabled=True,
        widget = forms.Textarea(),
        label = _('Coordinator Addendum'),
        help_text=_('The coordination team may add additional text about the vendor statements and status.'),
        required=False
    )

class CaseRoleForm(forms.Form):
    owner = forms.MultipleChoiceField(
        choices=(),
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}))

class ReportStatusForm(forms.Form):
    status = forms.MultipleChoiceField(
        choices=VTCaseRequest.STATUS_CHOICES,
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class':'ul_nobullet'}))


MESSAGE_STATUS_CHOICES = [(1, "Read"),
                          (2, "Unread"),
                          (3, "Deleted")]

class InboxFilterForm(forms.Form):
    keyword = forms.CharField(
        max_length=200,
        label='Keyword(s)',
        widget=forms.TextInput(attrs={'placeholder': 'Search by keyword',
                                      'class': 'asyncdelaysearch'
                                      }),
        required=False)

    status = forms.MultipleChoiceField(
        choices=MESSAGE_STATUS_CHOICES,
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}))


class LimitedCaseFilterForm(forms.Form):

    STATUS_FILTER_CHOICES = (
        (Case.ACTIVE_STATUS, _('Active')),
        (Case.INACTIVE_STATUS, _('Inactive')),
        (3, _('Published')),
    )

    wordSearch = forms.CharField(
        max_length=100,
        label='Keyword(s)',
	widget=forms.TextInput(attrs={'placeholder': 'Search by keyword',
                                      'class': 'asyncdelaysearch'}),
	required=False)

    status = forms.MultipleChoiceField(
        choices=STATUS_FILTER_CHOICES,
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}))

    page = forms.CharField(max_length=5,
                           required=False)



class CaseFilterForm(forms.Form):
    STATUS_FILTER_CHOICES = (
    (Case.ACTIVE_STATUS, _('Active')),
    (Case.INACTIVE_STATUS, _('Inactive')),
    (3, _('Published')),
    )

    wordSearch = forms.CharField(
        max_length=100,
        label='Keyword(s)',
        widget=forms.TextInput(attrs={'placeholder': 'Search by keyword',
                                      'class': 'asyncdelaysearch'}),
        required=False)
    status = forms.MultipleChoiceField(
        choices=STATUS_FILTER_CHOICES,
	required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'ul_nobullet'}))
    page = forms.CharField(max_length=5,
                           required=False)

    datestart = forms.DateField(required=False)
    dateend = forms.DateField(required=False)

    def __init__(self, *args, **kwargs):
        super(CaseFilterForm, self).__init__(*args, **kwargs)
        #self.fields['dateend'].initial = timezone.now


class VCPostalForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(VCPostalForm, self).__init__(*args, **kwargs)
        self.fields['street2'].required=False
        self.fields['version'].required=False

    class Meta:
        model=VinceCommPostal
        fields = "__all__"
        widgets = {'version': forms.HiddenInput()}


class VCPhoneForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(VCPhoneForm, self).__init__(*args, **kwargs)
        self.fields['comment'].required=False
        self.fields['version'].required=False

    class Meta:
        model=VinceCommPhone
        fields = "__all__"
        widgets = {'version': forms.HiddenInput()}

class VCEmailForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(VCEmailForm, self).__init__(*args, **kwargs)
        self.fields['version'].required=False

    def clean_email(self):
        email = self.cleaned_data['email']
        if email:
            email = email.strip()
        return email

    def clean_name(self):
        name = self.cleaned_data['name']
        if name:
            name = name.strip()
        return name

    class Meta:
        model = VinceCommEmail
        exclude = ["invited", "status", "email_function", "email_list"]
        widgets = {'version':forms.HiddenInput()}


class VCWebsiteForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(VCWebsiteForm,self).__init__(*args, **kwargs)
        self.fields['version'].required=False

    class Meta:
        model = VinceCommWebsite
        fields = "__all__"
        widgets = {'version':forms.HiddenInput() }

class VCPgPForm(forms.ModelForm):
    #pgp_key_data = forms.CharField(max_length=200,
    #                               required=False,
    #                               widget=forms.TextInput())

    def __init__(self, *args, **kwargs):
        super(VCPgPForm, self).__init__(*args, **kwargs)
        self.fields['startdate'].required=False
        self.fields['enddate'].required=False
        self.fields['pgp_protocol'].required=False
        self.fields['version'].required=False
        self.fields['pgp_key_id'].required=False
        self.fields['pgp_key_data'].required=False

    def clean_pgp_key_id(self):
        key_id = self.cleaned_data['pgp_key_id']
        if key_id != '':
            if search("[^0-9a-fA-F]", key_id) is not None:
                raise ValidationError("PGP Key ID may contain only hexadecimal characters")
        return key_id

    def clean(self):
        check = [self.cleaned_data.get('pgp_key_data'), self.cleaned_data['pgp_key_id']]
        if any(check):
            return self.cleaned_data
        raise ValidationError('Either PGP Key or ID is required')

    def clean_pgp_key_data(self):
        key_data = self.cleaned_data['pgp_key_data']
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

    class Meta:
        model = VinceCommPgP
        fields = "__all__"
        widgets = {'version':forms.HiddenInput(),
                   'pgp_key_id':forms.HiddenInput(),
                   'pgg_key_data': forms.Textarea(attrs={'placeholder': 'Paste PGP Key', 'rows': 4})}

class PreferencesForm(forms.Form):
    email_preference = forms.ChoiceField(
        choices=[(1, 'HTML'), (2, 'Plain Text')],
        label='Which email format do you prefer?',
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'}),
	required=False)

    email_all_activity = forms.BooleanField(
        label=_('Any posts on a case by a vendor.'),
        help_text=_('Lets you know if anyone makes changes to or posts in a case you\'re involved in.'),
        required=False,
    )

    email_coordinator_activity = forms.BooleanField(
        label=_('Any posts on a case by a coordinator.'),
        help_text=_('Lets you know if a coordinator makes changes to a case you\'re involved in.'),
        required=False,
    )

    email_reporter_activity = forms.BooleanField(
        label=_('Any posts on a case by a reporter.'),
        help_text=_('Lets you know if a reporter (usually the person that reported the vulnerability) makes changes to a case you\'re involved in.'),
        required=False,
    )

    """
    email_case_reminders = forms.BooleanField(
        label=_('Reminders about a case.'),
        help_text=_('Lets you know when a case is about to go public and if your action is required on a case you\'re involved in.'),
        required=False,
    )

    email_tags = forms.BooleanField(
        label=_('When you are tagged in a post.'),
        help_text=_('Lets you know when you or your organization is tagged in a post.'),
        required=False,
    )
    """

    email_daily = forms.ChoiceField(
        choices=[(1, 'Immediately'), (2, 'Once Daily')],
        label='How do you prefer to receive your case notifications?',
        help_text=_("You will still be notified immediately of any direct messages or if you're tagged in a post."),
        widget=forms.RadioSelect(attrs={'class':'ul_nobullet horizontal_bullet'}),
        required=False
    )

    def __init__(self, *args, **kwargs):
        super(PreferencesForm, self).__init__(*args, **kwargs)
        #if setting is not set for this user, set to default
        for x,y in DEFAULT_USER_SETTINGS.items():
            if self.initial.get(x) is None and x in self.fields:
                self.fields[x].initial=y



# phone numbers vary greatly world-wide, so best we can do is verify
# that no "weird" characters are entered.
def validate_phone_number(value):
    phone_re = "[^0-9()+.,\- ]" # set of all things except phone number characters and commas
    if search(phone_re, value) is not None:
        raise ValidationError('%s contains non-telephone characters' % value)

def validate_not_future_date(value):
    if value > date.today():
        raise ValidationError('%s is a future date' % value)

COORD_STATUS_CHOICES = [(1, "I have not attempted to contact any vendors"),
                        (2, "I have been unable to find contact information for a vendor"),
                        (3, "I have contacted vendors but not sent them details"),
                        (4, "I have sent details to vendors"),
                        (5, "None of these apply")]
WHY_NOT_CHOICES = [(1, 'I have not attempted to contact any vendors'),
                   (2, 'I have been unable to find contact information for a vendor'),
                   (3, 'Other')]

class CaseRequestForm(forms.ModelForm):
    contact_name = forms.CharField(
        max_length=100,
        label='Name',
        required=False,
        help_text='The name of the person submitting this form. You may use a pseudonym, alias, or handle in place of your real name.')
    contact_org = forms.CharField(
        max_length=100,
        required=False,
        label='Organization',
        help_text='The name of the organization you are reporting on behalf of, if applicable.')
    contact_email = forms.EmailField(
        label='Email address',
        required=False,
        widget=forms.TextInput(attrs={'placeholder': 'address@example.com'}),
        help_text='Your personal email address. Consider creating a free webmail account if you do not wish to share your email address.')
    reporter_pgp = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 4, 'placeholder': 'ASCII-armored public PGP key or URL (optional, but helps us communicate securely with you)'}),
        label='Public PGP key',
        max_length=100000000,
        required=False,
        help_text="Optionally, if you would like to use PGP encrypted email, please include either your ASCII-armored PGP key or a URL to your key."
    )
    contact_phone = forms.CharField(
        max_length=60,
        required=False,
        label='Telephone',
        validators=[validate_phone_number],
        help_text='The telephone where we may reach you if necessary',
        widget=forms.TextInput(attrs={'placeholder': '+1 412-268-7090'}))

    share_release = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Do you want us to share your contact information with vendors?',
        help_text='We will share contact information with vendors unless otherwise specified.',
        widget=forms.RadioSelect(attrs={'class' : 'ul_nobullet'}),
        required=True)

    credit_release = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Do you want to be acknowledged by name in any published document about this vulnerability?',
        help_text='If we publish a document based on this report, we will credit you unless otherwise specified.',
        widget=forms.RadioSelect(attrs={'class' : 'ul_nobullet'}),
        required=True)

    coord_status = forms.MultipleChoiceField(
        choices=COORD_STATUS_CHOICES, label="What coordination actions have you taken so far?",
        help_text="You must select at least one",
        required=False,
        widget=forms.CheckboxSelectMultiple(attrs={'class' : 'ul_nobullet'}))

    comm_attempt = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Have you contacted the vendor about this vulnerability?',
        required=True,
        widget=forms.RadioSelect(attrs={'class': 'ul_nobullet'}))

    why_no_attempt = forms.ChoiceField(
        choices=WHY_NOT_CHOICES, label="Why have you not contacted the vendor directly?",
        widget=forms.RadioSelect(attrs={'class': 'ul_nobullet'}),
        required=False)

    please_explain = forms.CharField(
        max_length=20000,
        widget=forms.Textarea(attrs={}),
        required=False)

    vendor_name = forms.CharField(
        max_length=100,
        label="Vendor Name",
        required=False,
        help_text="The name of the organization or company that develops the affected product.")

    multiplevendors = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label="Do you believe multiple vendors are affected?",
        widget=forms.RadioSelect(attrs={'class' : 'ul_nobullet'}),
        required=True)

    other_vendors = forms.CharField(
        max_length=1000,
        label="Please list the vendors, one vendor per line.",
        required=False,
        widget=forms.Textarea())

    first_contact = forms.DateField(
        label="Date of First Contact Attempt",
        input_formats=['%Y-%m-%d'],
        widget=forms.DateInput(attrs={'placeholder':'YYYY-MM-DD'}),
        validators=[validate_not_future_date],
        required=False)

    vendor_communication = forms.CharField(
        max_length=20000,
        label='Summary of previous vendor communications',
        widget=forms.Textarea(),
        required=False,
        help_text='What communications have you received from the vendor(s) so far? (max 20,000 chars)')

    product_name = forms.CharField(
        max_length=200,
        required=True,
        label='What is the name of the affected product or software?',
        help_text='This field will be used in the subject and/or body of an acknowledgment email from VINCE to help identify this report with its tracking number. Please DO NOT include any sensitive information in this field. Give the full product name such as "Food BarRouter ABC1200" or "FooSoft Office."',
        widget=forms.TextInput())

    product_version = forms.CharField(
        max_length=100,
        label='What version number of the product or software is affected?',
        required=True,
        help_text='Please include the version number you tested, such as 1.2.4, if known; otherwise put "unknown." A version number, firmware version, builder number, or release date is helpful for identifying affected products.',
        widget=forms.TextInput())

    ics_impact = forms.BooleanField(
        label='Significant ICS/OT impact?',
        required=False)
    
    vul_description = forms.CharField(
        max_length=20000,
        label='What is the vulnerability?',
        required=True,
        widget=forms.Textarea(attrs={'rows': 10}),
        help_text='Please describe the vulnerability in sufficient technical detail. Include a proof of concept if possible.  You may describe multiple vulnerabilities here rather than submitting multiple forms, if the vulnerabilities affect the same product. (max 20,000 chars)')

    vul_exploit = forms.CharField(
        max_length=20000,
        label='How does an attacker exploit this vulnerability?',
        help_text='Explain access or other conditions necessary to attack. (max 20,000 chars)',
        widget=forms.Textarea(),
        required=True)

    vul_impact = forms.CharField(
        max_length=20000,
        label='What does an attacker gain by exploiting this vulnerability? (i.e., what is the impact?)',
        help_text='Additional privileges, etc. Please be specific as possible. (max 20,000 chars)',
        widget=forms.Textarea(),
        required=True)

    vul_discovery = forms.CharField(
        max_length=20000,
        label='How was the vulnerability discovered?',
        help_text='Please note any specific tools or techniques used. (max 20,000 chars)',
        widget=forms.Textarea(),
        required=True)

    vul_public = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label="Is this vulnerability publicly known?",
        widget=forms.RadioSelect(attrs={'class' : 'ul_nobullet'}),
        required=True)

    public_references = forms.CharField(
        max_length=1000,
        label="Please provide references (max 1000 chars)",
        widget=forms.Textarea(attrs={'placeholder': 'URL(s)'}),
        required=False)

    vul_exploited = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Is there evidence that this vulnerability is being actively exploited?',
        widget=forms.RadioSelect(attrs={'class' : 'ul_nobullet'}),
        required=True)

    exploit_references = forms.CharField(
        max_length=20000,
        label="Please provide references",
        required=False,
        widget=forms.Textarea(attrs={'placeholder': 'URL(s)'}))

    vul_disclose = forms.ChoiceField(
        choices=[(True, 'Yes'), (False, 'No')],
        label='Do you plan to publicly disclose this vulnerability yourself?',
        required=True,
        widget=forms.RadioSelect(attrs={'class' : 'ul_nobullet'}))

    disclosure_plans = forms.CharField(
        max_length=1000,
        label="What are your public disclosure plans? (max 1000 chars)",
        widget=forms.Textarea(attrs={'placeholder': 'Include dates and events if applicable'}),
        required=False)

    user_file = forms.FileField(
        label='Upload File',
        help_text="You may specify one (1) related file to send us",
        required=False
    )
    tracking = forms.CharField(
        max_length=100,
        label='If you have one or more existing VINCE Tracking IDs for this submission, enter them below. Separate each tracking ID with a comma:',
        help_text='If you are following up with us regarding an existing VINCE Tracking ID, please enter it here.',
        required=False,
        widget=forms.TextInput(attrs={'placeholder': f'{settings.CASE_IDENTIFIER}nnnnnn, etc.'}))

    comments = forms.CharField(
        max_length=1000,
        label='Any additional comments that will not be shared with vendors:',
        help_text='Comments in this box will be kept private and will not be included in any publication or shared with vendors. (max 1000 chars)',
        required=False,
        widget=forms.Textarea())

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', '')
        super(CaseRequestForm, self).__init__(*args,**kwargs)

    class Meta:
        model = VTCaseRequest
        exclude = ["user", "vrf_id", "date_submitted", "status", "search_vector", "new_vuid", "coordinator"]

class CreateServiceAccount(forms.Form):

    send_email = forms.BooleanField(
        label = "Do you want this account to receive VINCE notifications?",
        help_text=('Uncheck the box below to prevent this email address from receiving case notifications'),
        required=False)
    
    email = forms.CharField(
	max_length=254,
        required=True,
        help_text=_('This will be the login username. Please note that this field is CASE SENSITIVE.'),
        label="Email address")

    preferred_username=forms.RegexField(label=_("Preferred Display Name"), max_length=254,
                                        help_text=_('This is a required VINCE account field but will not be used for service accounts'),
                                        regex=r'^[\w\+-_]+(\s[\w\+-_]+)*$', required=True,
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
        super(CreateServiceAccount, self).__init__(*args, **kwargs)
        self.fields['send_email'].initial = True

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
