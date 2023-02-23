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
from django.contrib.auth.models import User, Group
import datetime
import json

register = template.Library()

@register.filter
def due_date_chart(due_date):
    today = datetime.date.today()
    if due_date == None:
        return f"<div class=\"chart__bar start\" style=\"width:{5}%;\"></div>"
    diff = due_date.date() - today
    timeline = 45
    if (diff.days > 45):
        timeline = diff.days
    if diff.days > 3:
        perc = (timeline-diff.days)/timeline * 100
        if perc > 75:
            cl = "crunch"
        elif perc < 25:
            cl = "start"
        elif perc < 50:
            cl = "half"
        else:
            cl = "almost"
        return f"<div class=\"chart__bar {cl}\" style=\"width:{perc}%;\"></div>"
    elif diff.days > 0:
        perc = (timeline-diff.days)/timeline * 100
        return f"<div class=\"chart__bar overdue\" style=\"width:{perc}%;\"></div>"
    else:
        return f"<div class=\"chart__bar overdue\" style=\"width:100%;\"></div>"


@register.filter
def published_chart(due_date):
    return f"<div class=\"chart__bar published\" style=\"width:100%;\"></div>"


@register.filter
def actionlogo(action):
    if "removed" in action.title:
        return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"far fa-trash-alt\"></i></span></div>"
    elif "Post" in action.title:
        return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"far fa-sticky-note\"></i></span></div>"
    elif "view" in action.title:
        return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"far fa-eye\"></i></span></div>"
    elif "message" in action.title:
        return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"far fa-envelope\"></i></span></div>"
    elif "status" in action.title:
        return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"fas fa-exclamation-triangle\"></i></span></div>"
    elif "Opened" in action.title:
        return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"fas fa-plus-square\"></i></span></div>"
    elif "Added Vulnerability" in action.title:
        return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"fas fa-bug\"></i></span></div>"
    elif "Added Vendor" in action.title:
        return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"fas fa-user-plus\"></i></span></div>"
    else:
        return f"<div class=\"profile-pic text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\"><i class=\"fas fa-cogs\"></i></span></div>"

@register.filter
def vtuserlogo(user, imgclass):
    #look up vc user
    vcuser = User.objects.using('vincecomm').filter(username=user.username).first()
    if vcuser:
        if vcuser.vinceprofile.logo:
            return f"<img class=\"hide-for-small-only {imgclass}\" src=\"{vcuser.vinceprofile.logo}\">"
        else:
            return f"<div class=\"{imgclass} hide-for-small-only text-center\" style=\"background-color:{vcuser.vinceprofile.logocolor};\"><span class=\"logo-initial\">{vcuser.vinceprofile.initial}</span></div>"
    return f"<div class=\"{imgclass} hide-for-small-only text-center\" style=\"background-color:#b00;\"><span class=\"logo-initial\">{user.usersettings.preferred_username}</span></div>"

@register.filter
def teamlogo(team, imgclass):
    #lookup team
    g = team
    try:
        from vinny.models import VinceCommContact, GroupContact
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load VinceCommContact model.")
    vccontact = VinceCommContact.objects.using('vincecomm').filter(vendor_id=g.groupsettings.contact.id).first()
    gc = GroupContact.objects.filter(contact=vccontact).first()
    if gc and gc.get_logo():
        return f"<img class=\"hide-for-small-only {imgclass}\" src=\"{gc.get_logo()}\">"
    else:
        return f"<div class=\"{imgclass} text-center\" style=\"background-color:{gc.logocolor};\"><span class=\"logo-initial\">{gc.contact.vendor_name[0]}</span></div>"


@register.filter
def get_status(d, title):
    count = 0
    for thing in d:
        if title == "Open":
            if thing["status"] in [1, 2]:
                count += thing['count']
        if title == "Progress":
            if thing["status"] == 6:
                count = thing['count']
        if title == "Closed":
            if thing["status"] in [4, 3]:
                count = thing['count']
    return count
        
@register.filter
def comment_editable(comment):
    if "added a comment" in comment:
        return True
    return False


@register.filter
def is_json(a):
    if a:
        if a.startswith("{"):
            return True
        
    return False

@register.filter
def review(title, followup):
    if "review completed" in title:
        return True
    return False

@register.filter
def type_tags(tags, tag_type):
    from vince.models import TagManager
    return tags.filter(tag_type=tag_type)


@register.filter
def loadjson(data):
    if data:
        return json.loads(data)

@register.filter
def cve_complete(vul):
    try:
        from vince.models import CVEAllocation
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load CVEAllocation model.")
    if vul.cve:
        cve = CVEAllocation.objects.filter(vul=vul).first()
        if cve:
            if cve.complete():
                if cve.cveaffectedproduct_set.count():
                    return True
    return False
            
