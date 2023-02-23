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
from django import template
import random
import os

register = template.Library()

@register.filter
def postlogo(post, imgclass):
    try:
        from vinny.models import Post, CaseMember
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load Post model.")

    if post.group:
        if post.group.groupcontact.get_logo():
            return f"<img class=\"hide-for-small-only {imgclass}\" src=\"{post.group.groupcontact.get_logo()}\">"
        else:
            return f"<div class=\"{imgclass} text-center\" style=\"background-color:{post.group.groupcontact.logocolor};\"><span class=\"logo-initial\">{post.group.groupcontact.contact.vendor_name[0]}</span></div>"
        
    elif post.author:
        cm = CaseMember.objects.filter(group__in=post.author.groups.exclude(groupcontact__isnull=True), case=post.case).first()
        if cm:
            if cm.group.groupcontact.get_logo():
                return f"<img class=\"hide-for-small-only {imgclass}\" src=\"{cm.group.groupcontact.get_logo()}\">"
            else:
                return f"<div class=\"{imgclass} hide-for-small-only text-center\" style=\"background-color:{cm.group.groupcontact.logocolor};\"><span class=\"logo-initial\">{cm.group.groupcontact.contact.vendor_name[0]}</span></div>"
        else:
            if post.author.vinceprofile.logo:
                return f"<img class=\"hide-for-small-only {imgclass}\" src=\"{post.author.vinceprofile.logo}\">"
            else:
                return f"<div class=\"{imgclass} hide-for-small-only text-center\" style=\"background-color:{post.author.vinceprofile.logocolor};\"><span class=\"logo-initial\">{post.author.vinceprofile.initial}</span></div>"
    else:
        return f"<div class=\"{imgclass} text-center\" style=\"background-color:black;\"><span class=\"logo-initial\">?</span></div>"


@register.filter
def followupaction(followup):
    return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"fas fa-cogs\"></i></span></div>"
            
@register.filter
def userlogo(user, imgclass):
    if user:
        if user.vinceprofile.logo:
            return f"<img class=\"{imgclass}\" src=\"{user.vinceprofile.logo}\">"
        else:
            return f"<div class=\"{imgclass} text-center\" style=\"background-color:{user.vinceprofile.logocolor};\"><span class=\"logo-initial\">{user.vinceprofile.initial}</span></div>"
    return f"<div class=\"{imgclass} hide-for-small-only text-center\" style=\"background-color:#b00;\"></div>"

@register.filter
def grouplogo(group, imgclass):
    try:
        if group.group.groupcontact.get_logo():
            return f"<img class=\"{imgclass}\" src=\"{group.group.groupcontact.get_logo()}\">"
        else:
            return f"<div class=\"{imgclass} text-center\" style=\"background-color:{group.group.groupcontact.logocolor};\"><span class=\"logo-initial\">{group.group.groupcontact.contact.vendor_name[0]}</span></div>"
    except:
        #possibly no groupcontact
        return f"<img class=\"{imgclass}\" src=\"https://unsplash.it/{random.randint(1, 26)}/?random\">"


@register.filter
def gclogo(groupcontact, imgclass):
    try:
        if groupcontact.get_logo():
            return f"<img class=\"hide-for-small-only {imgclass}\" src=\"{groupcontact.get_logo()}\">"
        else:
            return f"<div class=\"{imgclass} text-center\" style=\"background-color:{groupcontact.logocolor};\"><span class=\"logo-initial\">{groupcontact.contact.vendor_name[0]}</span></div>"
    except:
        #possibly no groupcontact
        return f"<img class=\"hide-for-small-only {imgclass}\" src=\"https://unsplash.it/{random.randint(1, 26)}/?random\">"
    
@register.filter
def vendorvuls(vuls):
    try:
        from vinny.models import CaseVulnerability
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load CaseVulnerability model.")

    return vuls.filter(ask_vendor_status=True)

@register.filter
def last_status(status):
    try:
        from vinny.models import CaseMemberStatus
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load CaseMemberStatus model.")
        
    return status.order_by('date_modified')[0]

@register.filter
def statusvalue(status):
    try:
        status = int(status)
        if status == 1:
            return "Affected"
        elif status == 2:
            return "Not Affected"
        else:
            return "Unknown"
    except:
        return "Unknown"

@register.filter
def get_contact(user):
    try:
        from vinny.models import VinceCommEmail
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load VinceCommEmailContact.")

    return VinceCommEmail.objects.filter(email=user.email)
        

@register.filter
def showpreview(filename):
    name, extension = os.path.splitext(filename)
    if extension in [".png", ".jpeg", ".jpg", ".bmp", ".tiff", ".gif", ".svg"]:
        return True
    else:
        return False


@register.filter
def showfileicon(filename):
    name, extension = os.path.splitext(filename)
    if extension in [".doc", ".docx"]:
        return "<i class=\"far fa-file-word\"></i>"
    elif extension in [".xls", ".xlst"]:
        return "<i class=\"far fa-file-excel\"></i>"
    elif extension in [".ppt", ".pptx"]:
        return "<i class=\"far fa-file-powerpoint\"></i>"
    elif extension in [".pdf"]:
        return "<i class=\"far fa-file-pdf\"></i>"
    elif extension in [".zip", ".tar", ".tarz", ".bzip", ".7z"]:
        return "<i class=\"far fa-file-archive\"></i>"
    elif extension in [".png", ".jpeg", ".jpg", ".bmp", ".tiff", ".gif", ".svg"]:
        return "<i class=\"far fa-file-image\"></i>"
    else:
        return "<i class=\"far fa-file\"></i>"


@register.filter
def new_post_light(vuid, user):
    try:
        from vinny.models import Post, Case, CaseViewed
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in templatetags: Can't load Post, Case model.")
    #get last post time
    case = Case.objects.using('vincecomm').filter(vuid=vuid).first()
    if case:
        x = Post.objects.filter(case=case).exclude(author__username=user).order_by('-modified')
        if x:
            last_viewed = CaseViewed.objects.filter(user__username=user, case=case).first()
            if last_viewed:
                posts = x.filter(modified__gt=last_viewed.date_viewed)
                if posts:
                    return f"<span class=\"post_light unviewed\" title=\"This case has {len(posts)} new posts\"></span>"
                else:
                    return f"<span class=\"post_light viewed\" title=\"This case has no new posts\"></span>"
            return f"<span class=\"post_light unviewed\" title=\"You have never viewed this case\"></span>"

        #no posts                                                                                   
        return f"<span class=\"post_light noposts\" title=\"This case has no posts\"></span>"
    else:
        return f"<span class=\"post_light black\" title=\"This case is not in VinceComm\"></span>"
