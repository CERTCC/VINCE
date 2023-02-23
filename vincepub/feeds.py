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
from django.contrib.syndication.views import Feed
from django.core.cache import cache
from django.urls import reverse
from django.http import HttpResponseRedirect, HttpResponse
from vincepub.models import VUReport
from django.utils.feedgenerator import Atom1Feed
from django.utils.http import http_date
from django.template.loader import render_to_string
from calendar import timegm
import logging
from django.conf import settings

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class VinceAtom1Feed(Atom1Feed):
    # Subclass the Atom1Feed so we can add our own elements
    def add_item_elements(self, handler, item):
        super(VinceAtom1Feed, self).add_item_elements(handler, item)
        # after generating the normal feed data from parent, add the "content" element
        # wrap with a check for data--we don't want to break the whole feed if a VUReport
        # doesn't generate this data for some reason
        if 'content_data' in item:
            handler.addQuickElement("content", item['content_data'], {"type": "html"})


class LatestVulReportActivity(Feed):
    feed_type = VinceAtom1Feed
    title = "CERT Recently Published Vulnerability Notes"
    link = f"https://{settings.VINCEPUB_URL}/vuls/"
    feed_url = f"https://{settings.VINCEPUB_URL}/vuls/atomfeed/"
    subtitle = f"ATOM feed for the {settings.ORG_NAME} {settings.WEB_TITLE}"
    author_name = f"{settings.ORG_NAME}"
    author_email = f"{settings.CONTACT_EMAIL}"
    author_link = f"https://{settings.VINCEPUB_URL}"
    description_template = "feeds/latest_description.html"
    #title_template = "feeds/latest_title.html"
    
    def items(self):
        items = cache.get('latest_notes')
        if items == None:
            items = list(VUReport.objects.order_by('-datefirstpublished')[:15])
            cache.set('latest_notes', items)
        return items

    def item_title(self, item):
        return ("%s: %s" % (item.vuid, item.name))

    #def item_description(self, item):
    #    if item.clean_desc:
    #        return item.clean_desc
    #    else:
    #        return item.overview
    #

    def item_link(self, item):
        link = f"https://{settings.VINCEPUB_URL}/vuls/id/"+item.idnumber
        return link

    def item_pubdate(self, item):
        return item.datefirstpublished

    def item_updateddate(self, item):
        return item.dateupdated

    def item_extra_kwargs(self, item):
        # add extra entries to the item data for use in the feed generation
        content_data = render_to_string("feeds/latest_content.html", {'object': item})
        return {'content_data': content_data}

    def get_context_data(self, **kwargs):
        context = super(LatestVulReportActivity, self).get_context_data(**kwargs)
        return context

    def __call__(self, request, *args, **kwargs):
        try:
            obj = self.get_object(request, *args, **kwargs)
        except ObjectDoesNotExist:
            raise Http404('Feed object does not exist.')
        feedgen = self.get_feed(obj, request)
        response = HttpResponse(content_type='application/atom+xml; charset=utf-8')
        if hasattr(self, 'item_pubdate') or hasattr(self, 'item_updateddate'):
            # if item_pubdate or item_updateddate is defined for the feed, set
            # header so as ConditionalGetMiddleware is able to send 304 NOT MODIFIED
            response['Last-Modified'] = http_date(
                timegm(feedgen.latest_post_date().utctimetuple()))
        feedgen.write(response, 'utf-8')
        return response
