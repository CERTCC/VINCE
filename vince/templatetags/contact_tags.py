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
from django import template
from django.conf import settings
import json

register = template.Library()

@register.filter
def unpack_phones(phones):
    print("HONES")
    rows = ""
    for method, old, new in phones:
        z = []
        print("IN UNPACK PHONESE")
        print(method)
        if method == "add":
            z = new
            i = "<i class=\"fas fa-plus primary\"></i>"
        elif method == "remove":
            z = new
            i = "<i class=\"fas fa-minus warning\"></i>"
        for val, p in z:
            for s in p:
                (cc, num, t, name) = s
                rows = rows + f"<tr class=\"{method}row\"><td>{i} {method}</td><td>{cc} {num} (<i>{t}</i>)</td>"
                if name:
                    rows = rows + f"<td>{name}</td></tr>"
                else:
                    rows = rows + "<td></td></tr>"

    return rows

@register.filter
def unpack_postal(postal):
    rows = ""
    for method, old, new in postal:
        z = []
        if method == "add":
            z = new
            i = "<i class=\"fas fa-plus primary\"></i>"
        elif method == "remove":
            z = old
            i = "<i class=\"fas fa-minus warning\"></i>"
        for val, p in z:
            for	s in p:
                (c, t, street1, street2, city, state, zip) = s
                rows = rows + f"<tr class=\"{method}row\"><td>{i} {method}</td><td>{street1} {street2} {city} {state} {c} {zip} (<i>{t}</i>)</td></tr>"

    return rows


@register.filter
def unpack_web(webs):
    rows = ""
    for method, old, new in webs:
        z = []
        if method == "add":
            z =	new
            i =	"<i class=\"fas fa-plus primary\"></i>"
        elif method == "remove":
            z = old
            i =	"<i class=\"fas fa-minus warning\"></i>"
        for val, p in z:
            for s in p:
                (url, d) = s
                rows = rows + f"<tr class=\"{method}row\"><td>{i} {method}</td><td>{url}</td>"
                if d:
                    rows = rows + f"<td>{d}</td></tr>"
                else:
                    rows = rows + "<td></td></tr>"

    return rows

@register.filter
def unpack_email(emails):
    rows = ""
    for method, old, new in emails:
        z = []
        if method == "add":
            z = new
            i = "<i class=\"fas fa-plus primary\"></i>"
        elif method == "remove":
            z = old
            i = "<i class=\"fas fa-minus warning\"></i>"
        for val, p in z:
            for s in p:
                (email, t, name) = s
                rows = rows + f"<tr class=\"{method}row\"><td>{i} {method}</td><td>{email} ({t})</td>"
                if name:
                    rows = rows + f"<td>{name}</td></tr>"
                else:
                    rows = rows + "<td></td></tr>"

    return rows

@register.filter
def unpack_pgp(keys):
    rows = ""
    for method, old, new in keys:
        z = []
        if method == "add":
            z = new
            i = "<i class=\"fas fa-plus primary\"></i>"
        elif method == "remove":
            z = old
            i = "<i class=\"fas fa-minus warning\"></i>"
        for val, p in z:
            for s in p:
                (pgp_key_id, pgp_key_data, pgp_email) = s
                rows = rows + f"<tr class=\"{method}row\"><td>{i} {method}</td><td>{pgp_key_id}</td><td>{pgp_email}</td></tr>"

    return rows

@register.filter
def is_groupadmin(email, contact):
    try:
        from vince.models import GroupAdmin
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load GroupAdmin model.")
    return GroupAdmin.objects.filter(contact=contact, email__email=email).exists()


@register.filter
def bounce_email(comment):
    js = json.loads(comment)
    emails = []
    try:
        for e in js["bouncedRecipients"]:
            emails.append(e["emailAddress"])
    except:
        return []
    return emails

@register.filter
def bounce_subject(description):
    try:
        return description.split("Subject:", 1)[1]
    except:
        return ""
    

@register.filter
def vince_user_link(email):
    try:
        from django.contrib.auth.models import User
    except ImportError:
        if settings.DEBUG:
            raise template.TemplateSyntaxError("Error in template tags: Can't load User model.")

    return User.objects.using('vincecomm').filter(username=email).first()

