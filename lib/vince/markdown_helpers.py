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
from django.contrib.auth.models import User, Group
import markdown as md
from lib.vince.mdx_math import MathExtension
import bleach
from bleach_whitelist import generally_xss_safe, markdown_attrs
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class UserMentionExtension(md.Extension):

    UM_RE = r'\B((@(?![0-9]+$)(?!-)[-/a-zA-Z0-9+_.]{2,36})(\s[-/a-zA-Z0-9+_.]*)?)'

    def __init__(self, users=None, **kwargs):
        md.Extension.__init__(self)
        self.user_list = users

    def extendMarkdown(self, mde, md_globals={}):
        mde.inlinePatterns["user_mentions"] = UserMentionInlinePattern(self.UM_RE, users=self.user_list)

class UserMentionInlinePattern(md.inlinepatterns.Pattern):

    def __init__(self, pattern, users=None):
        md.inlinepatterns.Pattern.__init__(self, pattern)
        if users:
            self.user_lists = [d['value'] for d in users]
        else:
            self.user_lists = []
            
    def query_users(self, user_name):
        if self.user_lists:
            return User.objects.using('vincecomm').filter(vinceprofile__preferred_username=user_name, vinceprofile__preferred_username__in=self.user_lists).first()
        else:
            try:
                return User.objects.using('vincecomm').filter(vinceprofile__preferred_username=user_name).first()
            except:
                return None

    def query_groups(self, group_name):
        if self.user_lists:
            return Group.objects.using('vincecomm').filter(groupcontact__contact__vendor_name=group_name, groupcontact__contact__vendor_name__in=self.user_lists).first()
        else:
            try:
                # this will match on more than 1 space so group gets tagged, but it won't show tooltip
                return Group.objects.using('vincecomm').filter(groupcontact__contact__vendor_name__istartswith=group_name).first()
            except:
                return None
                    
    def handleMatch(self, m):
        user_name = m.group(3).replace("@", "")
        user_name_with_space = m.group(2).replace("@", "") 
        if (len(m.groups()) > 3):
            word_after_user_name = m.group(4)
        else:
            word_after_user_name = ""

        if self.user_lists:
            if user_name not in self.user_lists:
                if user_name_with_space not in self.user_lists:
                    return "@%s" % user_name_with_space

        # try group 2 (which includes the space):
        user_name = m.group(2).replace("@", "")
        user = self.query_users(user_name)
        if user:
            result = md.util.etree.Element('a')
            result.text = "@%s" % user_name
            result.set('href', user.vinceprofile.url)
            result.set('class', 'user-mention')
            return result

        group = self.query_groups(user_name)
        if group:
            result = md.util.etree.Element('a')
            result.text = "@%s" % user_name
            result.set('href', group.groupcontact.url)
            result.set('class', 'user-mention')
            return result

        #try group 1 (without space)
        user_name = m.group(3).replace("@", "")
        user = self.query_users(user_name)
        if user:
            result = md.util.etree.Element('a')
            result.text = "@%s" % user_name
            result.set('href', user.vinceprofile.url)
            result.set('class', 'user-mention')
            result.tail = word_after_user_name
            return result
        #or groupname
        group = self.query_groups(user_name)
        if group:
            result = md.util.etree.Element('a')
            result.text = "@%s" % user_name
            result.set('href', group.groupcontact.url)
            result.set('class', 'user-mention')
            result.tail = word_after_user_name
            return result
        
        result = "@%s" % user_name_with_space
        return result

    
def markdown(value):
    markdown_attrs['a'].append("class")
    markdown_attrs['img'].append("width")
    markdown_attrs['img'].append("height")
    return bleach.clean(md.markdown(value, extensions=['toc', 'markdown.extensions.fenced_code', UserMentionExtension(), MathExtension()]), generally_xss_safe, markdown_attrs)

def markdown_filter(value, users):
    markdown_attrs['a'].append("class")
    markdown_attrs['img'].append("width")
    markdown_attrs['img'].append("height")
    return bleach.clean(md.markdown(value, extensions=['toc', 'markdown.extensions.fenced_code', UserMentionExtension(users), MathExtension()]), generally_xss_safe, markdown_attrs)
