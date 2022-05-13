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

logger = logging.getLogger(__name__)


class VinnyRouter(object):
    """
    A router to contro all database operations on models in the vince application
    """

    def db_for_read(self, model, **hints):
        """
        If model is vince-track(bigvince), then use default database
        """
        logger.debug("VREAD")
        logger.debug(model)
        logger.debug(model._meta.app_label)
        if model._meta.app_label=="vinny":
            logger.debug("use vinny")
            return 'vincecomm'
        return None

    def db_for_read(self, model, **hints):
        """
        If model is vince-track(bigvince), then use default database
        """
        logger.debug(model)
        logger.debug(model._meta.app_label)
        if model._meta.app_label=="vinny":
            logger.debug("use vinny")
            return 'vincecomm'
        return None

    def allow_relation(self, obj1, obj2, **hints):
        logger.debug("Vrelation")
        if obj1._meta.app_label == obj2._meta.app_label:
            return True
        if (obj1._meta.app_label in ['vincecomm', 'vinny']) and (obj2._meta.app_label in ['vincecomm', 'vinny']):
            return False
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        All non-vincetrack models end up in this pool
        """
        logger.debug("Vmigrate")
        if db == "vincecomm":
            if app_label in ["vinny", "auth", "admin", "sessions", "contenttypes"]:
                return True
            else:
                return False
        else:
            if app_label == "vinny":
                return False
            else:
                return True
            

    
