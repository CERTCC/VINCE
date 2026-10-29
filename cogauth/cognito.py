"""
Timeout-bounded wrapper around the vendored warrant Cognito client.

Our Cognito user pool runs cross-region (us-east-2) while the apps run in
us-east-1, so every per-request token check is a cross-region network call.
The vendored ``lib.warrant.Cognito`` makes those calls with no timeout, which
means a slow/hung Cognito can freeze a gunicorn worker for far longer than the
90s worker timeout. With only 5 sync workers, a brief Cognito slowdown can
stall every worker at once and take the site down.

This subclass bounds those calls with explicit timeouts while leaving
``lib/warrant`` unmodified (so there are no vendored-code edits to carry across
library upgrades). Import ``Cognito`` from here instead of from ``lib.warrant``.
"""
import boto3
import requests
from botocore.config import Config
from django.conf import settings
from envs import env

from lib.warrant import Cognito as _Cognito

# (connect, read) seconds for the raw HTTPS JWKS fetch; tunable via settings so
# ops can adjust without a code change.
_COGNITO_HTTP_TIMEOUT = getattr(settings, "COGNITO_HTTP_TIMEOUT", (3.05, 7))

# Bounds the boto3 cognito-idp client. Worst case ~ max_attempts * (connect +
# read) = 2 * (3 + 7) = 20s, comfortably under the 90s gunicorn worker timeout.
_COGNITO_BOTO_CONFIG = Config(
    connect_timeout=3,
    read_timeout=7,
    retries={"max_attempts": 2},
)


class Cognito(_Cognito):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Warrant builds an un-bounded cognito-idp client in its __init__;
        # replace it with one that has explicit timeouts. ``self.client`` is the
        # same attribute warrant reassigns in its own switch_session(), so this
        # is a supported seam, not a hack. Assumes IAM-role credentials -- our
        # call sites never pass access_key/secret_key to Cognito().
        self.client = boto3.client(
            "cognito-idp",
            region_name=self.user_pool_region,
            config=_COGNITO_BOTO_CONFIG,
        )

    def get_keys(self):
        # Mirrors lib.warrant.Cognito.get_keys, adding a timeout to the JWKS
        # fetch. Reached via verify_token() on login and token refresh. Kept in
        # sync with warrant's implementation (the COGNITO_JWKS short-circuit).
        try:
            return self.pool_jwk
        except AttributeError:
            pool_jwk_env = env("COGNITO_JWKS", {}, var_type="dict")
            if len(pool_jwk_env.keys()) > 0:
                self.pool_jwk = pool_jwk_env
                return self.pool_jwk
            self.pool_jwk = requests.get(
                "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json".format(
                    self.user_pool_region, self.user_pool_id
                ),
                timeout=_COGNITO_HTTP_TIMEOUT,
            ).json()
            return self.pool_jwk
