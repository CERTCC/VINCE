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
from django.contrib import admin
from django.contrib.auth.admin import GroupAdmin as BaseGroupAdmin
from django.contrib.auth.models import Group
from vinny.models import GroupContact, VinceProfile, VinceCommContact, Case, Thread, VinceCommInvitedUsers, VinceCommEmail, VinceCommGroupAdmin, VCVulnerabilityNote, CaseMemberStatus, CaseStatement, VinceAttachment, VinceTrackAttachment, CaseVulnerability, CaseTracking, CoordinatorSettings, VTCaseRequest, CaseMember, CaseViewed
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth import views as auth_views
from django.contrib.admin.views.decorators import staff_member_required
from cogauth.views import COGLoginView
from django.conf import settings

class MultiDBModelAdmin(admin.ModelAdmin):
    class Media:
        css = {
            'all': ('css/admin/my_own_admin.css',)
            }
    # A handy constant for the name of the alternate database.
    using = 'vincecomm'
    actions = ['delete_selected']

    def save_model(self, request, obj, form, change):
        # Tell Django to save objects to the 'other' database.
        obj.save(using=self.using)

    def delete_model(self, request, obj):
        # Tell Django to delete objects from the 'other' database
        obj.delete(using=self.using)

    def delete_selected(self, request, queryset):
        for obj in queryset:
            print(obj)
            obj.delete(using=self.using)
        if queryset.count() == 1:
            message_bit = "1 user was"
        else:
            message_bit = "%s users were" % queryset.count()
        self.message_user(request, "%s successfully deleted.")
        
    def get_queryset(self, request):
        # Tell Django to look for objects on the 'other' database.
        return super().get_queryset(request).using(self.using)

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        # Tell Django to populate ForeignKey widgets using a query
        # on the 'other' database.
        return super().formfield_for_foreignkey(db_field, request, using=self.using, **kwargs)

    def formfield_for_manytomany(self, db_field, request, **kwargs):
        # Tell Django to populate ManyToMany widgets using a query
        # on the 'other' database.
        return super().formfield_for_manytomany(db_field, request, using=self.using, **kwargs)


# Register your models here.

class GroupInline(admin.StackedInline):
    model = GroupContact
    can_delete = False
    verbose_name_plural = 'Group Vendor Contact'

class GroupSettingsInline(admin.StackedInline):
    model = CoordinatorSettings
    can_delete=False
    verbose_name_plural = 'Coordinator Settings'
    
class GroupAdmin(BaseGroupAdmin):
    inlines = (GroupInline, GroupSettingsInline)
    list_display = ('name', 'get_vendor_name')
    search_fields=['name', 'groupcontact__contact__vendor_name']
    
    def get_vendor_name(self, instance):
        if instance.groupcontact:
            if instance.groupcontact.contact:
                return instance.groupcontact.contact.vendor_name

        return "Group"
    get_vendor_name.short_description = "Vendor Group Name"

class CognitoProfileInline(admin.StackedInline):
    model = VinceProfile
    can_delete = False
    verbose_name_plural = "Vince Profile"
    fk_name = 'user'
    
class CustomUserAdmin(BaseUserAdmin, MultiDBModelAdmin):
    inlines = (CognitoProfileInline, )
    list_display = ('username', 'first_name', 'last_name', 'is_staff', 'email', 'get_preferred_username')
    list_select_related = ('vinceprofile',)
    actions=['get_preferred_username']

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False

    def	get_form(self, request, obj=None, **kwargs):
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
        return instance.vinceprofile.preferred_username
    get_preferred_username.short_description = "Visible"
    
    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(CustomUserAdmin, self).get_inline_instances(request, obj)

class VinnyAdminSite(admin.AdminSite):
    site_header = "VinceComm Administration"
    site_title = "VinceComm"
    index_title = "VinceComm Site Administration"



vinnyadmin = VinnyAdminSite('vinnyadmin')
vinnyadmin.logout = auth_views.LogoutView.as_view(template_name='cogauth/logout.html')
vinnyadmin.login = staff_member_required(COGLoginView.as_view(template_name='vince/admin_login.html'), login_url = settings.LOGIN_URL)

vinnyadmin.register(User, CustomUserAdmin)
#Re-register GroupAdmin

vinnyadmin.register(Group, GroupAdmin)
vinnyadmin.site_url = "/vince/comm/dashboard/"


class VinceCommEmailContactInLine(admin.TabularInline):
    model = VinceCommEmail

class ContactAdmin(admin.ModelAdmin):
    search_fields=['vendor_id', 'vendor_name']
    list_display=['vendor_id', 'vendor_name', 'active', "_emails"]

    inlines = [
        VinceCommEmailContactInLine
    ]

    def _emails(self, obj):
        return obj.get_emails()

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False
    
class GroupAdminAdmin(admin.ModelAdmin):
    list_display = ['email', 'contact', 'get_email_vendor']
    search_fields = ['email__email', 'contact__vendor_name']
    readonly_fields = ['email', 'contact']

    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False

    def get_email_vendor(self, instance):
        if instance.email:
            if instance.email.contact:
                return instance.email.contact.vendor_name
        return "Email"

    get_email_vendor.short_description = "Email Contact Name"


class CaseViewedAdmin(admin.ModelAdmin):
    list_display = ('get_vuid', 'user')

    def get_vuid(self, instance):
        return instance.case.vuid
    
class CaseAdmin(admin.ModelAdmin):
    list_display = ('vuid', 'title', 'created', 'status', 'published', 'get_team_owner')
    list_filter = ('status',)
    search_fields = ['vuid', 'title']
    fields = ['vuid', 'created', 'modified', 'status', 'summary', 'title', 'due_date', 'get_team_owner']
    readonly_fields = fields
    actions=['get_team_owner']
    
    def has_delete_permission(self, request, obj=None):
        if request.user.is_superuser:
            return True
        return False

    def get_team_owner(self, instance):
        if instance.team_owner:
            return instance.team_owner.groupcontact.contact.vendor_name
        else:
            return "None set"
    get_team_owner.short_description = "Team Owner"
        

class CaseMemberAdmin(admin.ModelAdmin):
    search_fields = ['case__vuid', 'case__title', 'group__groupcontact__contact__vendor_name',  'participant__email']
    
vinnyadmin.register(VinceCommContact, ContactAdmin)
vinnyadmin.register(Case, CaseAdmin)
#vinnyadmin.register(Thread)
vinnyadmin.register(VinceCommInvitedUsers)
vinnyadmin.register(VinceCommGroupAdmin, GroupAdminAdmin)
vinnyadmin.register(VCVulnerabilityNote)
vinnyadmin.register(CaseMemberStatus)
vinnyadmin.register(CaseStatement)
vinnyadmin.register(VinceAttachment)
vinnyadmin.register(VinceTrackAttachment)
vinnyadmin.register(CaseTracking)
vinnyadmin.register(CaseViewed, CaseViewedAdmin)
#vinnyadmin.register(CaseMember, CaseMemberAdmin)
#vinnyadmin.register(VTCaseRequest)
#vinnyadmin.register(CaseVulnerability)
