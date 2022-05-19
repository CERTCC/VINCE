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
from django.contrib import admin, messages
from django.conf import settings
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.admin import GroupAdmin as BaseGroupAdmin
from django.contrib.auth.models import User, Group
from django.contrib.auth import get_user_model
from django.contrib.auth import views as auth_views
from django.contrib.admin.views.decorators import staff_member_required
from django.utils.translation import ugettext_lazy as _
from vince.models import TicketQueue, Ticket, FollowUp, CaseTemplate, UserSettings, Contact, QueuePermissions, CasePermissions, TicketThread, CaseAssignment, CaseAction, ContactAssociation, CaseParticipant, CalendarEvent, VulNote, BounceEmailNotification
from vince.models import TicketChange, Attachment, VulnerabilityCase, EmailTemplate, EmailContact, AdminPGPEmail, Artifact, Vulnerability, VendorStatus, VulnerableVendor, VinceSMIMECertificate, UserRole, VinceReminder, GroupSettings, TagManager
from vinny.models import Thread, Message, VTCaseRequest, CaseMember, VendorAction
from django.contrib.admin.helpers import ActionForm
from cogauth.views import COGLoginView

from vincepub.models import VUReport, VulnerabilityNote, NoteVulnerability, Vendor, VendorRecord

# Register your models here.


class QueuePermissionInline(admin.TabularInline):
    model = QueuePermissions

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False
    
@admin.register(TicketQueue)
class QueueAdmin(admin.ModelAdmin):
    list_display = ('title', 'slug', 'default_owner')
    prepopulated_fields = {"slug": ("title",)}
    inlines = [QueuePermissionInline,]

    def has_delete_permission(self, request, obj=None):
        return False

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        is_superuser = request.user.is_superuser
        disabled_fields = set()

        if not is_superuser:
            disabled_fields |= {
                'group',
                'group_read'
                'group_write',
            }

        for f in disabled_fields:
            if f in form.base_fields:
                form.base_fields[f].disabled = True

        return form


    
class CasePermissionInline(admin.TabularInline):
    model = CasePermissions

class CaseParticipantInline(admin.TabularInline):
    model = CaseParticipant

def bulk_reassign(modeladmin, request, queryset):
    ct = queryset.count()
    if int(request.POST['user']) == 0:
        title = "Bulk unassign ticket by {request.user.usersettings.vince_username}"
    else:
        assignee = User.objects.get(id=request.POST['user']).usersettings.vince_username
        title = f"Bulk reassign ticket to user {assignee} by {request.user.usersettings.vince_username}"

    for x in queryset:
        ca = FollowUp(ticket=x, title=title, user=request.user)
        ca.save()
    
    if int(request.POST['user']) == 0:
        queryset.update(assigned_to=None)
    else:
        queryset.update(assigned_to=request.POST['user'])
    messages.success(request, f"Successfully updated {ct} tickets")
    
bulk_reassign.short_description = 'Reassign tickets to another user'


def bulk_tktstatuschange(modeladmin, request, queryset):
    ct = queryset.count()
    status_dict = dict(Ticket.STATUS_CHOICES)
    
    for x in queryset:
        title = f"Bulk ticket status change to {status_dict[int(request.POST['status'])]} by {request.user.usersettings.vince_username}"
        ca = FollowUp(ticket=x, title=title, user=request.user)
        ca.save()
        
    queryset.update(status = request.POST['status'])
    
    messages.success(request, f"Successfully updated {ct} tickets")

bulk_tktstatuschange.short_description = 'Change ticket status'


def bulk_casestatuschange(modeladmin, request, queryset):
    ct = queryset.count()
    status_dict = dict(VulnerabilityCase.STATUS_CHOICES)
    for x in queryset:
        title = f"Bulk case status change to {status_dict[int(request.POST['status'])]} by {request.user.usersettings.vince_username}"
        ca = CaseAction(case=x, user=request.user, title=title, action_type=0)
        ca.save()
    queryset.update(status = request.POST['status'])
    messages.success(request, f"Successfully updated {ct} cases")

bulk_casestatuschange.short_description = 'Change case status'

def bulk_moveticket(modeladmin, request, queryset):
    ct = queryset.count()
    if request.POST.get('case') != "":
        case = VulnerabilityCase.objects.filter(vuid=request.POST['case']).first()
        queue = TicketQueue.objects.filter(slug="case").first()
        if case and queue:
            queryset.update(case=case, queue=queue)
            messages.success(request, f"Successfully updated {ct} tickets")
        else:
            messages.error(request, f"Case doesn't exist")
    else:
        messages.error(request, f"Case doesn't exist")
bulk_moveticket.short_description = "Move Tickets to Case Queue"

def bulk_reassign_cases(modeladmin, request, queryset):
    ct = queryset.count()
    if int(request.POST['user']) == 0:
        assignee = "None"
    else:
        assignee = User.objects.get(id=request.POST['user']).usersettings.vince_username

    for x in queryset:
        title = f"Bulk reassign owner to user {assignee} by {request.user.usersettings.vince_username}"
        ca = CaseAction(case=x, user=request.user, title=title, action_type=0)
        ca.save()

    if int(request.POST['user']) == 0:
        queryset.update(owner=None)
    else:
        queryset.update(owner=request.POST['user'])

    messages.success(request, f"Successfully updated {ct} cases")

bulk_reassign_cases.short_description = 'Change case ownership to another user'

def bulk_add_user_case(modeladmin, request, queryset):
    ct = queryset.count()
    if int(request.POST['user']) > 0:
        for x in queryset:
            assignee = User.objects.get(id=request.POST['user'])
            CaseAssignment.objects.get_or_create(assigned=assignee, case=x)
            title = f"Bulk assigned user {assignee.usersettings.vince_username} by {request.user.usersettings.vince_username}"
            ca = CaseAction(case=x, user=request.user, title=title, action_type=0)
            ca.save()
        messages.success(request, f"Successfully updated {ct} cases")
    else:
        messages.error(request, f"Use bulk unassigment action to unassign user from case")

bulk_add_user_case.short_description = "Add user to case assignment"

def bulk_unassign_user_case(modeladmin, request, queryset):
    ct = queryset.count()
    if int(request.POST['user']) > 0:
        for x in queryset:
            assignee = User.objects.get(id=request.POST['user'])
            CaseAssignment.objects.filter(assigned=assignee, case=x).delete()
            title = f"Bulk unassigned user {assignee.usersettings.vince_username} by {request.user.usersettings.vince_username}"
            ca = CaseAction(case=x, user=request.user, title=title, action_type=0)
            ca.save()
        messages.success(request, f"Successfully updated {ct} cases")
    else:
        messages.error(request, f"Please select a user to unassign from selected cases")
bulk_unassign_user_case.short_description = "Unassign user from all selected cases"

class BulkAssignmentForm(ActionForm):
    try:
        USER_CHOICES = [(0, '--------')] + [(q.id, q.usersettings.preferred_username) for q in get_user_model().objects.all()]
    except:
        USER_CHOICES = []
        
    user = forms.ChoiceField(choices=USER_CHOICES,
                             label=_('Assign a User'),
                             required=False
    )

    status = forms.ChoiceField(choices=Ticket.STATUS_CHOICES,
                               label=_('Change Ticket Status'),
                               required=False)

    case = forms.CharField(label=_('Case ID Number'),
                           required=False)
    

class CaseBulkAssignmentForm(ActionForm):
    try:
        USER_CHOICES = [(0, '--------')] + [(q.id, q.usersettings.preferred_username) for q in get_user_model().objects.all()]
    except:
        USER_CHOICES = []

    user = forms.ChoiceField(choices=USER_CHOICES,
                             label=_('Assign a User'),
                             required=False
    )

    status = forms.ChoiceField(choices=VulnerabilityCase.STATUS_CHOICES,
                               label=_('Change Case Status'),
                               required=False
                               )

class CaseAssignedFilter(admin.SimpleListFilter):
    title = "Assigned"
    parameter_name = 'assigned_to'

    def lookups(self, request, model_admin):
        return [(0, '--------')] + [(q.id, q.username) for q in get_user_model().objects.all()]

    def queryset(self, request, queryset):
        if self.value() == 0:
            assignments = CaseAssignment.objects.all().values_list('case__id', flat=True)
            return queryset.exclude(id__in=assignments)
        elif self.value():
            assignments = CaseAssignment.objects.filter(assigned=self.value()).values_list('case__id', flat=True)
            return queryset.filter(id__in=assignments)
        else:
            return queryset


        
@admin.register(VulnerabilityCase)
class VinceCaseAdmin(admin.ModelAdmin):
    list_display = ('vuid', 'title', 'team_owner', 'created', 'owner', 'status', 'product_name', 'case_get_assigned_to')
    inlines = [CasePermissionInline, CaseParticipantInline, ]
    search_fields = ('vuid', 'title', 'product_name')
    list_filter = ('team_owner', 'owner', 'status', CaseAssignedFilter)
    action_form = CaseBulkAssignmentForm
    actions = [bulk_reassign_cases, bulk_add_user_case, bulk_unassign_user_case, bulk_casestatuschange]

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False
    
    def case_get_assigned_to(self, obj):
        return obj.get_assigned_to

    case_get_assigned_to.short_description = _('Users assigned')
    
@admin.register(EmailTemplate)
class EmailTemplateAdmin (admin.ModelAdmin):
   list_display = ('template_name', 'subject', 'heading', 'plain_text', 'locale' )
   search_fields = ('template_name', 'locale', 'heading')
   list_filter = ('locale', )
   
   def has_delete_permission(self, request, obj=None):
        return False


class AssignedFilter(admin.SimpleListFilter):
    title = "Filter by Assigned"
    parameter_name = 'assigned_to'
    
    def lookups(self, request, model_admin):
        return [(0, '--------')] + [(q.id, q.username) for q in get_user_model().objects.all()]
    def queryset(self, request, queryset):
        return queryset.filter(assigned_to=self.value())
    
    
@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    search_fields=['title', 'case__vuid']
    list_display = ('title', 'status', 'assigned_to', 'queue', )
    date_hierarchy = 'created'
    list_filter = ('queue', 'assigned_to', 'status')
    action_form = BulkAssignmentForm
    list_per_page = 250
    actions = [bulk_reassign, bulk_tktstatuschange, bulk_moveticket]

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False
    
    def hidden_submitter_email(self, ticket):
        if ticket.submitter_email:
            username, domain = ticket.submitter_email.split("@")
            username = username[:2] + "*" * (len(username) - 2)
            domain = domain[:1] + "*" * (len(domain) - 2) + domain[-1:]
            return "%s@%s" % (username, domain)
        else:
            return ticket.submitter_email

        
class TicketChangeInline(admin.StackedInline):
    model = TicketChange

class AttachmentInline(admin.StackedInline):
    model = Attachment


class ReminderAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'created_by', 'alert_date')
    list_filter = ('user', 'alert_date', 'created_by')
    list_per_page = 250

    def has_delete_permission(self, request, obj=None):
        if request.user.is_staff:
            return True
        return False
    
@admin.register(FollowUp)
class FollowUpAdmin(admin.ModelAdmin):
    inlines = [TicketChangeInline, AttachmentInline]
    list_display = ('ticket_get_ticket_for_url', 'title', 'date', 'ticket', 'user', 'new_status')
    list_filter = ('user', 'date', 'new_status')

    def ticket_get_ticket_for_url(self, obj):
        return obj.ticket.ticket_for_url
    ticket_get_ticket_for_url.short_description = _('Slug')

    
class UserSettingsInline(admin.StackedInline):
    model=UserSettings
    can_delete=False
    verbose_name_plural='UserSettings'
    fk_name='user'
    fields=('org', 'preferred_username', 'case_template', 'contacts_read', 'contacts_write')

class CustomUserAdmin(UserAdmin):
    inlines=(UserSettingsInline,)
    list_display = ('username', 'first_name', 'last_name', 'get_preferred_username')
    list_select_related = ('usersettings',)
    actions=['get_preferred_username']


    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False
    
    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        is_superuser = request.user.is_superuser
        disabled_fields = set()

        if not is_superuser:
            disabled_fields |= {
                'username',
                'is_superuser',
                'email',
                'user_permissions',
            }

        if (not is_superuser
            and obj is not None
            and obj == request.user
        ):
            disabled_fields |= {
                'is_staff',
                'is_superuser',
                'groups',
                'user_permissions',
            }
            
        for f in disabled_fields:
            if f in form.base_fields:
                form.base_fields[f].disabled = True

        return form
    
    def get_preferred_username(self, instance):
        return instance.usersettings.preferred_username
    get_preferred_username.short_description = "Visible"
    
    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(CustomUserAdmin, self).get_inline_instances(request, obj)

class EmailContactInLine(admin.TabularInline):
    model = EmailContact

    
class ContactAdmin(admin.ModelAdmin):
    search_fields=['vendor_name']
    list_display=['vendor_name', 'vendor_type', 'active', "_emails"]

    inlines = [
        EmailContactInLine
    ]
    
    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False
    
    def _emails(self, obj):
        return obj.get_emails()
    
#admin.site = CustomAdminSite("default")

class AdminPGPEmailAdmin(admin.ModelAdmin):
    fields = ('pgp_key_data', 'pgp_key_id', 'email', 'name', 'active')
    list_display = ('pgp_key_id', 'email', 'name', 'active')

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False

class VulAdmin(admin.ModelAdmin):
    list_display = ('get_vul_id', 'cve', 'case', 'description')
    search_fields=['description', 'case__vuid', 'cve']
    actions = ['get_vul_id']
    title = "Deleted Vulnerabilities"
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.filter(deleted=True)

    def get_vul_id(self, instance):
        return instance.vul
    get_vul_id.short_description = "Vul ID"

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False

class VulVendorAdmin(admin.ModelAdmin):
    search_fields = ['case__vuid', 'case__title', 'vendor', 'contact__vendor_name']
    list_filter = ('deleted', )
    
    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False


class MessageInline(admin.TabularInline):
    model = Message
    fields = ('content', 'created')

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False
    
class ThreadAdmin(admin.ModelAdmin):
    list_display = ('id', 'subject', 'to_group', 'from_group', 'case')
    inlines = [MessageInline,]
    
    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False

class CaseMemberAdmin(admin.ModelAdmin):
    search_fields = ['case__vuid', 'case__title', 'group__groupcontact__contact__vendor_name',  'participant__email']
    
class VUReportInline(admin.TabularInline):
    model = VUReport

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False

class TrackVulNoteAdmin(admin.ModelAdmin):
    search_fields = ['case__vuid', 'case__title']
    list_display = ['case']

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False
    
class VulNoteAdmin(admin.ModelAdmin):
    search_fields = ['vuid', 'title']
    list_display = ['vuid', 'title']
    fields = ['vuid', 'title', 'dateupdated', 'datefirstpublished', 'revision_number', 'publicdate', 'published']
    readonly_fields = ['vuid', 'title', 'dateupdated', 'datefirstpublished', 'revision_number']

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False

class VUReportAdmin(admin.ModelAdmin):
    search_fields = ['vuid', 'name', 'idnumber']
    list_display = ('vuid', 'name',)
    readonly_fields = ['vuid', 'idnumber', 'name', 'overview', 'vulnote', 'search_vector', 'clean_desc', 'impact', 'resolution', 'workarounds', 'sysaffected', 'thanks', 'author', 'public'] 
    
    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False

class VulPubAdmin(admin.ModelAdmin):

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False
    

class VulPubVendorAdmin(admin.ModelAdmin):
    search_fields = ['vendor']
    
    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False

class VulPubVendorRecord(admin.ModelAdmin):
    search_fields = ['vendor', 'vuid', 'idnumber']

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False

class VTCaseRequestAdmin(admin.ModelAdmin):
    list_display = ['vrf_id', 'product_name', 'vendor_name', 'user', 'new_vuid','date_submitted', 'coordinator']
    search_fields = ['vrf_id', 'product_name', 'new_vuid', 'vendor_name']


class TagManagerAdmin(admin.ModelAdmin):
    list_display = ['tag', 'description', 'tag_type', 'team']
    search_fields = ['tag', 'description']
    
class GroupInline(admin.StackedInline):
    model = GroupSettings
    can_delete = False
    verbose_name_plural = 'Group Settings'
    
class GroupAdmin(BaseGroupAdmin):
    inlines = (GroupInline, )
    list_display = ('name', 'get_org_name')

    def get_org_name(self, instance):
        if instance.groupsettings:
            return instance.groupsettings.organization

        return "-"
    get_org_name.short_description = "Organization Name"

class BounceAdmin(admin.ModelAdmin):
    list_display = ['email', 'ticket', 'bounce_date', 'bounce_type', 'action_taken']
    search_fields = ['email', 'subject']
    
admin.site.login = staff_member_required(COGLoginView.as_view(template_name='vince/admin_login.html'), login_url = settings.LOGIN_URL)
admin.site.logout = auth_views.LogoutView.as_view(template_name='vince/tracklogout.html')

admin.site.site_header = "VinceTrack Admin"
admin.site.site_title = "VinceTrack Admin Portal"
admin.site.index_title = "Welcome to VinceTrack Portal"
admin.site.site_url = "/vince/dashboard/"

admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
admin.site.unregister(Group)
admin.site.register(Group, GroupAdmin)
admin.site.register(CaseTemplate)
admin.site.register(Contact, ContactAdmin)
admin.site.register(Vulnerability, VulAdmin)
admin.site.register(VinceSMIMECertificate)
#admin.site.register(TicketThread)
admin.site.register(AdminPGPEmail, AdminPGPEmailAdmin)
#admin.site.register(Artifact)
admin.site.register(VulnerableVendor, VulVendorAdmin)
admin.site.register(Thread, ThreadAdmin)
admin.site.register(VulnerabilityNote, VulNoteAdmin)
admin.site.register(VUReport, VUReportAdmin)
admin.site.register(NoteVulnerability, VulPubAdmin)
admin.site.register(Vendor, VulPubVendorAdmin)
admin.site.register(VendorRecord, VulPubVendorRecord)
admin.site.register(UserRole)
admin.site.register(ContactAssociation)
admin.site.register(TagManager, TagManagerAdmin)
admin.site.register(VinceReminder, ReminderAdmin)
admin.site.register(VTCaseRequest, VTCaseRequestAdmin)
admin.site.register(CalendarEvent)
admin.site.register(VulNote, TrackVulNoteAdmin)
admin.site.register(CaseMember, CaseMemberAdmin)
admin.site.register(VendorAction)
admin.site.register(BounceEmailNotification, BounceAdmin)
