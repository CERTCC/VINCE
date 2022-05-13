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
import logging
import threading

request_cfg = threading.local()

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class DatabaseRouterMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        return response

    def process_view(self, request, view_func, args, kwargs):

        if "comm" in request.path:
            request_cfg.cfg = "vincecomm"
        elif 'vuls' in request.path:
            request_cfg.cfg = "vincepub"
        else:
            if hasattr(request_cfg, 'cfg'):
                del request_cfg.cfg

    def process_response(self, request, response):
        if hasattr(request_cfg, 'cfg'):
            del request_cfg.cfg

        return response


class BigVinceRouter(object):
    """
    A router to contro all database operations on models in the vince application
    """

    def _default_db(self):
        
        if hasattr(request_cfg, 'cfg'):
            return request_cfg.cfg
        else:
            return None
    
    def db_for_read(self, model, **hints):
        """
        If model is vince-track(bigvince), then use default database
        """
        if model._meta.app_label=="vinny":
            return 'vincecomm'
        elif model._meta.app_label == "cogauth":
            return 'vincecomm'
        elif model._meta.app_label=="vincepub":
            return 'vincepub'
        elif model._meta.app_label == "vince":
            return None
        return self._default_db()

    def db_for_write(self, model, **hints):
        """
        If model is vince-track(bigvince), then use default database
        """
        if model._meta.app_label=="vinny":
            return 'vincecomm'
        elif model._meta.app_label=='cogauth':
            return 'vincecomm'
        elif model._meta.app_label == 'vincepub':
            return 'vincepub'
        elif model._meta.app_label == "vince":
            return None
        return self._default_db()

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._meta.app_label == obj2._meta.app_label:
            return True
        if (obj1._meta.app_label in ['vincecomm', 'vinny']) and (obj2._meta.app_label in ['vincecomm', 'vinny']):
            return False
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        All non-vincetrack models end up in this pool
        """
        return True
#
#        if db == "vincecomm":
#            if app_label in ["vinny", "auth", "admin", "sessions", "contenttypes"]:
#                return True
#            else:
#                return False
#        else:
#            if app_label == "vinny":
#                return False
#            else:
#                return True
#            

    
