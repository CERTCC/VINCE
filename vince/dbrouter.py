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
import logging
import os
import socket
import threading

request_cfg = threading.local()


def _diag_server_id():
    """Instance:pid that served a request (login-loop diagnostics). Never raises."""
    try:
        return f"{socket.gethostname()}:{os.getpid()}"
    except Exception:
        return "UNKNOWN"


def _diag_prefetch(request):
    """Speculative/prefetch markers (Chrome Sec-Purpose, Safari/older Purpose,
    Firefox X-Moz). Returns the first header present, else "". Never raises.
    NB: Safari address-bar preload may send NO distinctive header, so "" does
    NOT rule out a prefetch -- only a non-empty value is a positive signal."""
    try:
        for h in ("HTTP_SEC_PURPOSE", "HTTP_PURPOSE", "HTTP_X_PURPOSE", "HTTP_X_MOZ"):
            v = request.META.get(h)
            if v:
                return f"{h[5:].replace('_', '-').title()}={v}"
        return ""
    except Exception:
        return "UNKNOWN"

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


class SessionCookieLifecycleMiddleware:
    """
    TEMPORARY diagnostic for the VINCE Comm login loop. MUST be listed FIRST in
    MIDDLEWARE (outermost layer) so its response-phase code runs AFTER Django's
    SessionMiddleware has set/blanked the session cookie -- that is the only
    position from which we can observe the final Set-Cookie that actually goes
    to the browser.

    For login/MFA-related requests, and for ANY response that sets or blanks the
    session cookie, logs the whole cookie lifecycle in one line (tagged
    [LOGINLOOP] so it shows up in the same CloudWatch query as the other
    login-loop diagnostics):
      - host the request arrived on
      - the sessionid cookie the browser SENT (present? key?)
      - the Set-Cookie the server is RETURNING: value blanked? max-age/expires?
        domain/path attributes? (the full new key, so it can be correlated to
        the next request's incoming cookie)
      - response status + redirect Location

    This discriminates the two live explanations for session_key=None at /mfa/:
      - HOST FLIP:   the incoming host on the password POST differs from the
                     host on the following /mfa/ GET (host-only cookie dropped).
      - COOKIE WIPE: a response carries Set-Cookie: sessionid=""; Max-Age=0,
                     so the browser discards the cookie before the next request.

    Logs only opaque session keys + booleans/attributes (consistent with the
    other temporary diagnostics). Remove after diagnosis.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # get_response is the ONLY statement outside the try: its exceptions must
        # propagate to Django's handler, never be swallowed. Everything the
        # diagnostic touches is inside the try, so the diagnostic can never break
        # a request (important: this middleware is outermost / runs on every request).
        response = self.get_response(request)

        try:
            from django.conf import settings

            cookie_name = getattr(settings, "SESSION_COOKIE_NAME", "sessionid")
            incoming = request.COOKIES.get(cookie_name)

            path = getattr(request, "path", "")
            is_auth_path = "/login" in path or "/mfa" in path

            try:
                morsel = response.cookies.get(cookie_name)
            except Exception:
                morsel = None

            # Django blanks the cookie by returning value "" with max-age 0 (and
            # an expiry in the past). That is the loop's cookie-wipe signature.
            blanked = morsel is not None and (
                morsel.value == "" or str(morsel.get("max-age")) == "0"
            )

            # Only log the interesting requests: anything touching login/MFA, or
            # any response anywhere that blanks the session cookie (the wipe
            # signature). Keeps volume down vs. logging every cookie-setting response.
            if is_auth_path or blanked:
                try:
                    host = request.get_host()
                except Exception:
                    host = "UNKNOWN"

                location = response.get("Location", "") if response.status_code in (301, 302) else ""

                if morsel is None:
                    set_cookie = "unchanged"
                else:
                    # SameSite/Secure (theory 1), scheme attrs included: a cookie set
                    # SameSite=Strict or Secure-over-http is silently withheld next request.
                    set_cookie = (
                        f"value={'EMPTY' if morsel.value == '' else morsel.value!r}, "
                        f"max-age={morsel.get('max-age')!r}, expires={morsel.get('expires')!r}, "
                        f"domain={morsel.get('domain')!r}, path={morsel.get('path')!r}, "
                        f"samesite={morsel.get('samesite')!r}, secure={bool(morsel.get('secure'))}, "
                        f"httponly={bool(morsel.get('httponly'))}"
                    )

                # Client identity + path to correlate the ~6 simultaneous users and
                # trace one user end-to-end (theory 7: no IP/username anywhere today).
                client_ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", ""))
                # username is only present pre-MFA if the session still holds it.
                try:
                    sess_username = request.session.get("username")
                except Exception:
                    sess_username = None

                # Proxy / cookie-stripping signals (theory 3): did OTHER cookies survive
                # when sessionid didn't? which proxy hops touched this request?
                cookie_names = sorted(request.COOKIES.keys())
                csrftoken_present = getattr(settings, "CSRF_COOKIE_NAME", "csrftoken") in request.COOKIES
                # Raw header reveals DUPLICATE sessionid cookies that request.COOKIES hides (theory 4).
                raw_cookie = request.META.get("HTTP_COOKIE", "")
                dup_sessionid = raw_cookie.count(cookie_name + "=")
                scheme = "https" if request.is_secure() else "http"
                xf_proto = request.META.get("HTTP_X_FORWARDED_PROTO", "")
                via = request.META.get("HTTP_VIA", "")
                ua = request.META.get("HTTP_USER_AGENT", "")[:120]

                # Which instance/worker served this (theory 5: instance/worker hopping).
                server_id = _diag_server_id()

                logger.debug(
                    "[LOGINLOOP] Session-cookie lifecycle: "
                    f"host={host!r}, scheme={scheme}, xf_proto={xf_proto!r}, path={path}, "
                    f"status={response.status_code}, redirect_to={location!r}, "
                    f"client_ip={client_ip!r}, session_username={sess_username!r}, "
                    f"incoming_sessionid={incoming!r}, dup_sessionid_in_header={dup_sessionid}, "
                    f"csrftoken_present={csrftoken_present}, cookie_names={cookie_names}, "
                    f"blanked={blanked}, set_cookie=({set_cookie}), "
                    f"prefetch={_diag_prefetch(request)!r}, "
                    f"via={via!r}, server={server_id}, ua={ua!r}"
                )
        except Exception as diag_err:
            try:
                logger.debug(f"[LOGINLOOP] Session-cookie lifecycle diagnostics failed to run: {diag_err}")
            except Exception:
                pass

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


class SessionBounceDiagnosticMiddleware:
    """
    TEMPORARY diagnostic for the intermittent VINCE Comm/Track login loop
    (user logs in + MFA, loads one page, then is bounced back to /login/ on the
    next request even though the DB is healthy and no logout() is logged).

    Fires ONLY when a request that ARRIVED WITH a sessionid cookie is being
    redirected to the login page -- i.e. the server treated an apparently
    logged-in user as anonymous. For that one request it logs:
      - whether a sessionid cookie was present, and its key
      - the router's per-thread DB selection (request_cfg.cfg) at response time
      - for each candidate DB alias on this server: does a session row for that
        key exist, and does the decoded session carry _auth_user_id

    Reading of the signals:
      - no sessionid cookie present             -> cookie not returned by client
      - cookie present, NO row in any DB        -> row cycled/deleted; key mismatch
      - cookie present, row w/ auth in vincecomm but user bounced anyway
                                                -> the in-request session read hit
                                                   the WRONG database (router race)
      - cookie present, row present but no auth -> session exists, auth was cleared

    Logs no secrets (only the opaque session key + booleans). Remove after diagnosis.
    Listed near the END of MIDDLEWARE so it can read request_cfg before the router
    middleware clears it.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # get_response is the ONLY statement outside the try (its exceptions must
        # propagate, never be swallowed); all diagnostic work is guarded.
        response = self.get_response(request)

        try:
            from django.conf import settings

            session_cookie = request.COOKIES.get(getattr(settings, "SESSION_COOKIE_NAME", "sessionid"))
            location = response.get("Location", "") if response.status_code in (301, 302) else ""
            # Only the bounce-to-login case, and only when a cookie was actually
            # sent (a lost session, not a fresh anonymous visitor).
            if "/login" not in location or not session_cookie:
                return response

            from django.contrib.sessions.models import Session
            from django.contrib.sessions.backends.db import SessionStore

            router_cfg = getattr(request_cfg, "cfg", None)
            decoder = SessionStore()

            per_db = {}
            for alias in ("default", "vincecomm", "vincepub"):
                if alias not in settings.DATABASES:
                    continue
                try:
                    row = Session.objects.using(alias).filter(session_key=session_cookie).first()
                    if row is None:
                        per_db[alias] = "no-row"
                    else:
                        data = decoder.decode(row.session_data)
                        per_db[alias] = "has_auth" if data.get("_auth_user_id") else "row-no-auth"
                except Exception as e:
                    per_db[alias] = f"err:{e}"

            user = getattr(request, "user", None)
            try:
                request_host = request.get_host()
            except Exception:
                request_host = "UNKNOWN"
            client_ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", ""))
            ua = request.META.get("HTTP_USER_AGENT", "")[:120]
            server_id = _diag_server_id()

            # --- REASON CAPTURE: WHY did this request's session read empty? ---
            # All read-only. We run FIRST on the response path (this middleware is
            # innermost), so request.session here is the state the view left --
            # exactly what SessionMiddleware is about to see before it wipes the cookie.
            from django.utils import timezone

            # (a) The request's OWN session object. is_empty() True requires the
            #     session_key to have been nulled -> the request-start load missed.
            try:
                req_session_key = request.session.session_key
            except Exception as e:
                req_session_key = f"err:{e}"
            try:
                req_is_empty = request.session.is_empty()
            except Exception as e:
                req_is_empty = f"err:{e}"
            try:
                req_keys = sorted(request.session.keys())
            except Exception as e:
                req_keys = f"err:{e}"

            # (b) Live replay of Django's own load for the SAME cookie, right now.
            #     replay found + request empty => the original load missed TRANSIENTLY
            #     (race/connection); replay also misses => persistent.
            try:
                rstore = SessionStore(session_key=session_cookie)
                rdata = rstore.load()  # independent DB read; nulls rstore.session_key on miss
                replay = (
                    f"found={bool(rdata)}, has_auth={bool(rdata.get('_auth_user_id'))}, "
                    f"key_after_load={rstore.session_key!r}"
                )
            except Exception as e:
                replay = f"err:{e}"

            # (c) Expiry probe: the row, its expire_date, the APP server's now() (the
            #     clock the real load's filter uses -- invisible to a psql now()), and
            #     whether the expiry-FILTERED query (what _get_session_from_db runs)
            #     still finds it. expire_gt_now False on a present row == expiry is the cause.
            try:
                now = timezone.now()
                row2 = Session.objects.using("default").filter(session_key=session_cookie).first()
                if row2 is None:
                    expiry = f"no-row-in-default, app_now={now.isoformat()}"
                else:
                    get_with_expiry = Session.objects.using("default").filter(
                        session_key=session_cookie, expire_date__gt=now
                    ).exists()
                    expiry = (
                        f"expire_date={row2.expire_date.isoformat()}, app_now={now.isoformat()}, "
                        f"expire_gt_now={row2.expire_date > now}, get_with_expiry_finds={get_with_expiry}"
                    )
            except Exception as e:
                expiry = f"err:{e}"

            logger.debug(
                "[LOGINLOOP] Session-bounce diagnostics: "
                f"path={request.path}, redirect_to={location!r}, "
                f"host={request_host!r}, client_ip={client_ip!r}, "
                f"sessionid_present=True, session_key={session_cookie!r}, "
                f"router_thread_local_cfg={router_cfg!r}, "
                f"user_authenticated_at_response={getattr(user, 'is_authenticated', None)}, "
                f"session_row_by_db={per_db}, "
                f"req_session_key={req_session_key!r}, req_is_empty={req_is_empty}, req_keys={req_keys}, "
                f"replay_load=({replay}), expiry=({expiry}), "
                f"prefetch={_diag_prefetch(request)!r}, "
                f"server={server_id}, ua={ua!r}"
            )
        except Exception as diag_err:
            try:
                logger.debug(f"Session-bounce diagnostics failed to run: {diag_err}")
            except Exception:
                pass

        return response

    
