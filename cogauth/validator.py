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
import json

import jwt
import requests
from django.conf import settings
from django.core.cache import cache
from django.utils.functional import cached_property
from jwt.algorithms import RSAAlgorithm

class TokenError(Exception):
    pass


class TokenValidator:
    def __init__(self, aws_region, aws_user_pool, audience):
        self.aws_region = aws_region
        self.aws_user_pool = aws_user_pool
        self.audience = audience

    @cached_property
    def pool_url(self):
        return "https://cognito-idp.%s.amazonaws.com/%s" % (
            self.aws_region,
            self.aws_user_pool,
        )

    @cached_property
    def _json_web_keys(self):
        response = requests.get(self.pool_url + "/.well-known/jwks.json")
        response.raise_for_status()
        json_data = response.json()
        return {item["kid"]: json.dumps(item) for item in json_data["keys"]}

    def _get_public_key(self, token):
        try:
            headers = jwt.get_unverified_header(token)
        except jwt.DecodeError as exc:
            raise TokenError(str(exc))

        if getattr(settings, "COGNITO_PUBLIC_KEYS_CACHING_ENABLED", False):
            cache_key = "django_cognito_jwt:%s" % headers["kid"]
            jwk_data = cache.get(cache_key)

            if not jwk_data:
                jwk_data = self._json_web_keys.get(headers["kid"])
                timeout = getattr(settings, "COGNITO_PUBLIC_KEYS_CACHING_TIMEOUT", 300)
                cache.set(cache_key, jwk_data, timeout=timeout)
        else:
            jwk_data = self._json_web_keys.get(headers["kid"])

        if jwk_data:
            return RSAAlgorithm.from_jwk(jwk_data)


    def validate(self, token):
        public_key = self._get_public_key(token)
        if not public_key:
            raise TokenError("No key found for this token")

        try:
            jwt_data = jwt.decode(
                token,
                public_key,
                audience=self.audience,
                issuer=self.pool_url,
                algorithms=["RS256"],
            )
        except (jwt.InvalidTokenError, jwt.ExpiredSignature, jwt.DecodeError) as exc:
            raise TokenError(str(exc))
        return jwt_data
