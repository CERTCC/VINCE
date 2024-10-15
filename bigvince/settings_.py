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
"""
Django settings for bigvince project.

Generated by 'django-admin startproject' using Django 2.11713.7.

For more information on this file, see
https://docs.djangoproject.com/en/2.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.1/ref/settings/
"""

import json
import logging.config
import os

import boto3
import environ
import urllib

env = environ.Env(DEBUG=(bool, False))
environ.Env.read_env()

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_DIR = environ.Path(__file__) - 3

# any change that requires database migrations is a minor release
VERSION = "3.0.8"

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env("SECRET_KEY")

VINCE_DEV_SYSTEM = os.environ.get("VINCE_DEV_SYSTEM", "")
if VINCE_DEV_SYSTEM == "1":
    VINCE_DEV_SYSTEM = "title-dev"

LOCALSTACK = os.environ.get("LOCALSTACK")

TERMS_URL = os.environ.get(
    "TERMS_URL", "https://docs.aws.amazon.com/cognito/latest/developerguide/data-protection.html"
)

GOOGLE_SITE_KEY = os.environ.get("GOOGLE_SITE_KEY")

GOOGLE_RECAPTCHA_SECRET_KEY = os.environ["GOOGLE_RECAPTCHA_SECRET_KEY"]

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env("DEBUG")

# build a list of trusted domains that includes our own domains.
# this gets used for ALLOWED_HOSTS and also CSRF_TRUSTED_ORIGINS

trusted_domains = []
if os.environ.get("AWS_DEPLOYED"):
    for host in list(
        {os.environ.get("VINCE_PUB_DOMAIN"), os.environ.get("VINCE_COMM_DOMAIN"), os.environ.get("VINCE_TRACK_DOMAIN")}
    ):
        if len(host.split(".")) < 3:
            trusted_domains.append(host)
        else:
            trusted_domains.append(host[host.index(".") :])

ALLOWED_HOSTS = ["127.0.0.1", "localhost", ".elasticbeanstalk.com", ".elb.amazonaws.com"] + trusted_domains

# When bigvince is deployed as an Elastic Beanstalk application,
# the Elastic LoadBalancer will try to do health checks using the internal
# IP address of the EC2 running the application.  We need to add that IP address
# to the ALLOWED_HOSTS.  Otherwise, the health check will fail and the pandas will be sad.
import requests

EC2_PRIVATE_IP = None
try:
    EC2_PRIVATE_IP = requests.get("http://169.254.169.254/latest/meta-data/local-ipv4", timeout=0.1).text
except requests.exceptions.RequestException:
    pass

if EC2_PRIVATE_IP:
    ALLOWED_HOSTS.append(EC2_PRIVATE_IP)

LOGIN_REDIRECT_URL = "vinny:dashboard"
MFA_REDIRECT_URL = "cogauth:mfaauth"
LOGIN_URL = "cogauth:login"

# Time zone support.
USE_TZ = True
DEFAULT_TIME_ZONE = "UTC"

# Application definition

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",
    "vince",
    "vinny",
    "vincepub",
    "cogauth",
    "bakery",
    "qr_code",
    "rest_framework",
    "django.contrib.admin",
    "widget_tweaks",
    "django.contrib.humanize",
    "django_countries",
    "storages",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "vince.dbrouter.DatabaseRouterMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "vince.middleware.TimezoneMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "vince.middleware.MultipleDomainMiddleware",
]

# When sending emails containing links to tickets/cases
# this server name will be used.  i.e: SERVER_NAME/vince/ticket/70
SERVER_NAME = os.environ.get("SERVER_NAME", "http://localhost:8000")

# If we are deployed in S3, we store the static files in S3.  Set this up
if os.environ.get("AWS_DEPLOYED"):
    AWS_REGION = os.environ.get("AWS_REGION")
    AWS_DEPLOYED = True
    AWS_DEFAULT_ACL = None
    if LOCALSTACK:
        AWS_S3_ENDPOINT_URL = os.environ.get("AWS_S3_ENDPOINT_URL")
        LOGGER_HANDLER = "console"
    else:
        LOGGER_HANDLER = "watchtower"
    AWS_STORAGE_BUCKET_NAME = os.environ.get("AWS_STORAGE_BUCKET_NAME")
    AWS_S3_REGION_NAME = os.environ.get("AWS_REGION")
    # Tell django-storages the domain to use to refer to static files.
    AWS_S3_CUSTOM_DOMAIN = os.environ.get("AWS_S3_CUSTOM_DOMAIN")
    AWS_LOCATION = os.environ.get("AWS_LOCATION")
    if os.environ.get("BUCKET_URL"):
        STATIC_URL = os.environ.get("BUCKET_URL") + "/"
    else:
        STATIC_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/{AWS_LOCATION}/"
    # Tell the staticfiles app to use S3Boto3 storage when writing the collected static files (when
    # you run `collectstatic`).
    STATICFILES_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"
    # set to True if you want VINCE to write a contacts backup file to an S3 directory,
    # you must also set ANCIENT_SRMAIL_BUCKET to S3 arn
    # To reload contacts into VINCE, set INITIAL_CONTACT_FILE and
    # uncomment code in vince/management/commands/loadinitialdata.py
    WRITE_SRMAIL = False
    # ANCIENT_SRMAIL_BUCKET=os.environ.get('ANCIENT_SRMAIL_BUCKET')
    if VINCE_DEV_SYSTEM == "title-dev":
        EMAIL_BACKEND = os.environ.get("EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend")
    else:
        EMAIL_BACKEND = "django_ses.SESBackend"
    # AWS_UPDATE_QUEUE = os.environ.get('AWS_UPDATE_QUEUE')
    S3_INCOMING_REPORTS = os.environ.get("S3_INCOMING_REPORTS")
    # for vincepub this is the bucket to update the website from LN
    S3_UPDATE_BUCKET_NAME = os.environ.get("S3_UPDATE_BUCKET_NAME")

    # This is required due to read-only nature of EC2
    BAKERY_FILESYSTEM = "mem://"
    BUILD_DIR = "mem:/bakery"

    # Due to the ACL requirement for VINCETrack, a separate domain is required
    # for the 'vince' app. This is used in the MultipleDomainMiddleware to
    # force Django to redirect to the correct domain depending on the
    # URL requested.  If the entire application is running under 1 domain - this is
    # not necessary
    MULTIURL_CONFIG = {
        "vince": os.environ.get("VINCE_TRACK_DOMAIN"),
        "vinny": os.environ.get("VINCE_COMM_DOMAIN"),
        "vincepub": os.environ.get("VINCE_PUB_DOMAIN"),
        "cogauth": os.environ.get("VINCE_COMM_DOMAIN"),
    }
    # if MULTIURL CONFIG set this below, otherwise set to SERVER_NAME
    KB_SERVER_NAME = f'https://{os.environ.get("VINCE_COMM_DOMAIN")}'
    KB_SHARED_BUCKET = os.environ.get("S3_KB_SHARED_BUCKET_NAME")
else:
    # this is the configuration for running locally - you still need some
    # some AWS variables set
    AWS_DEPLOYED = False
    LOGGER_HANDLER = "console"
    #    EMAIL_BACKEND = os.environ.get('EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend')
    EMAIL_BACKEND = os.environ.get("EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend")
    EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.vince.example")
    EMAIL_PORT = os.environ.get("EMAIL_PORT", 25)

    # BELOW IS FOR A LOCAL (DEBUG) setup - use the local static directory
    STATIC_URL = "/static/"
    KB_STATIC_URL = STATIC_URL
    # AWS_UPDATE_QUEUE = os.environ.get('AWS_UPDATE_QUEUE')
    S3_INCOMING_REPORTS = "vince-reports"
    AWS_REGION = os.environ.get("AWS_REGION", "us-east-2")
    MULTIURL_CONFIG = False
    BUILD_DIR = "/local/dir/static/notes"
    KB_SERVER_NAME = SERVER_NAME

    # BAKERY_FILESYSTEM = 'mem://'
    # BUILD_DIR="mem:/bakery"
    WRITE_SRMAIL = False


# VRF_PRIVATE_MEDIA_LOCATION is the folder within the S3_INCOMING_REPORTS
# bucket to store any files that are uploaded with the vulnerability reports
VRF_PRIVATE_MEDIA_LOCATION = "VRF_uploaded_files"
# VRF_REPORT_DIR is the folder within the S3_INCOMING_REPORTS bucket to write
# incoming vul reports
VRF_REPORT_DIR = "VRF_submissions"

# AWS_PRIVATE_MEDIA_LOCATION is the folder within PRIVATE_BUCKET_NAME to store
# files
AWS_PRIVATE_MEDIA_LOCATION = "vince_attachments"

# PRIVATE_BUCKET_NAME is the S3 bucket name where files are stored for each
# application (VINCETrack and VINCEComm) - these are auto-generated by CDK
PRIVATE_BUCKET_NAME = os.environ.get("PRIVATE_BUCKET_NAME", "vince-shared")
# VINCE_SHARED_BUCKET is the VINCEComm PRIVATE_BUCKET_NAME, but needs to be
# separate so that VINCETrack can access it.
VINCE_SHARED_BUCKET = os.environ.get("VINCE_SHARED_BUCKET_NAME", PRIVATE_BUCKET_NAME)
# VP_PRIVATE_BUCKET_NAME is the name of the S3 bucket where vulnerability reports
# are stored
VP_PRIVATE_BUCKET_NAME = os.environ.get("S3_INCOMING_REPORTS", "vince-pub-reports")

PRIVATE_FILE_STORAGE = "bigvince.storage_backends.PrivateMediaStorage"

AWS_DEFAULT_ACL = None

AWS_S3_OBJECT_PARAMETERS = {"ContentDisposition": "attachment"}

# SQS/SNS
VINCE_TRACK_SNS_ARN = os.environ.get("VINCE_TRACK_SNS_ARN")
VINCE_ERROR_SNS_ARN = os.environ.get("VINCE_ERROR_SNS_ARN")
# if this is VINCE_TRACK - then use the VINCE TRACK ARN
VINCE_COMM_SNS_ARN = os.environ.get("VINCE_COMM_SNS_ARN", VINCE_TRACK_SNS_ARN)

ROOT_URLCONF = "bigvince.urls"

# These are BAKERY variables
AWS_BUCKET_NAME = os.environ.get("AWS_STORAGE_BUCKET_NAME")

BAKERY_GZIP = True
GZIP_CONTENT_TYPES = (
    "application/atom+xml",
    "application/javascript",
    "application/json",
    "application/ld+json",
    "application/manifest+json",
    "application/rdf+xml",
    "application/rss+xml",
    "application/schema+json",
    "application/vnd.geo+json",
    "application/vnd.ms-fontobject",
    "application/x-font-ttf",
    "application/x-javascript",
    "application/x-web-app-manifest+json",
    "application/xhtml+xml",
    "application/xml",
    "font/eot",
    "font/opentype",
    "image/bmp",
    "image/svg+xml",
    "image/vnd.microsoft.icon",
    "image/x-icon",
    "text/cache-manifest",
    "text/css",
    "text/html",
    "text/javascript",
    "text/plain",
    "text/vcard",
    "text/vnd.rim.location.xloc",
    "text/vtt",
    "text/x-component",
    "text/x-cross-domain-policy",
    "text/xml",
)

BAKERY_CACHE_CONTROL = {"text/html": 300, "application/javascript": 86400}


BAKERY_VIEWS = (
    "vincepub.views.VUDetailView",
    "vincepub.views.VUDetail404",
    "vincepub.views.SecurityTxtView",
)


TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "vince.context_processors.vince_version",
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
            "libraries": {
                "staticfiles": "django.templatetags.static",
            },
        },
    },
]

WSGI_APPLICATION = "bigvince.wsgi.application"

# set to 5 days 60*24*5*60
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_AGE = 432000


def get_secret(secret_arn):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=os.environ.get("AWS_REGION"))
    secrets = client.get_secret_value(SecretId=secret_arn)
    return json.loads(secrets["SecretString"])


SUPERUSER = None

# Credentials are stored in AWS Secret's Manager
if os.environ.get("AWS_SECRET_MANAGER", None):
    VINCE_NAMESPACE = os.environ.get("VINCE_NAMESPACE")

    SUPERUSER = get_secret(os.environ.get("VINCE_SUPERUSER_AUTH"))

    # ATTACHMENT_URL = AWS_S3_CUSTOM_DOMAIN + "/vince/comm/attachments"

    if VINCE_NAMESPACE == "vince":
        LOGIN_URL = "vince:login"
        LOGIN_REDIRECT_URL = "vince:dashboard"
        vince_track_secrets = get_secret(os.environ.get("VINCE_TRACK_AUTH"))
        vincetrack_user = vince_track_secrets["username"]
        vincetrack_password = vince_track_secrets["password"]
        vincetrack_db = vince_track_secrets["username"]
        # if MULTIURL_CONFIG is defined, this should also be defined. otherwise: BIG PROBLEMO.
        MFA_REDIRECT_URL = "vince:mfaauth"
        # VC_ATTACHMENT_URL = ATTACHMENT_URL
        # this needs to go to vincetrack namespace
        # ATTACHMENT_URL = AWS_S3_CUSTOM_DOMAIN + "/vince/attachments"

    if VINCE_NAMESPACE in ["vince", "vinny"]:
        vince_comm_secrets = get_secret(os.environ.get("VINCE_COMM_AUTH"))
        vincecomm_user = vince_comm_secrets["username"]
        vincecomm_password = vince_comm_secrets["password"]
        vincecomm_db = vince_comm_secrets["username"]

    vince_pub_secrets = get_secret(os.environ.get("VINCE_PUB_AUTH"))
    vincepub_user = vince_pub_secrets["username"]
    vincepub_password = vince_pub_secrets["password"]
    vincepub_db = vince_pub_secrets["username"]

# Check environment variables for database credentials
else:
    VINCE_NAMESPACE = "vince"
    SUPERUSER = {"username": "superuser@example.com", "password": "SavingTheWorldWithPerl"}
    vincetrack_user = os.environ.get("VINCE_TRACK_DB_USER", "vincetrack")
    vincetrack_password = os.environ.get("VINCE_TRACK_DB_PASS", "vincetrack")
    vincetrack_db = os.environ.get("VINCE_TRACK_DB_NAME", "vincetrack")

    vincecomm_user = os.environ.get("VINCE_COMM_DB_USER", "vincecomm")
    vincecomm_password = os.environ.get("VINCE_COMM_DB_PASS", "vincecomm")
    vincecomm_db = os.environ.get("VINCE_COMM_DB_NAME", "vincecomm")

    vincepub_user = os.environ.get("VINCE_PUB_DB_USER", "vincepub")
    vincepub_password = os.environ.get("VINCE_PUB_DB_PASS", "vincepub")
    vincepub_db = os.environ.get("VINCE_PUB_DB_NAME", "vincepub")


DATABASES = {"default": {}}
if VINCE_NAMESPACE == "vince":
    DATABASES["default"] = {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": vincetrack_db,
        "USER": vincetrack_user,
        "PASSWORD": vincetrack_password,
        "HOST": os.environ.get("VINCE_TRACK_DB_HOST", "localhost"),
        "PORT": os.environ.get("VINCE_TRACK_DB_PORT", 5432),
    }

if VINCE_NAMESPACE in ["vince", "vinny"]:
    DATABASES["vincecomm"] = {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": vincecomm_db,
        "USER": vincecomm_user,
        "PASSWORD": vincecomm_password,
        "HOST": os.environ.get("VINCE_COMM_DB_HOST", "localhost"),
        "PORT": os.environ.get("VINCE_COMM_DB_PORT", 5432),
    }

DATABASES["vincepub"] = {
    "ENGINE": "django.db.backends.postgresql_psycopg2",
    "NAME": vincepub_db,
    "USER": vincepub_user,
    "PASSWORD": vincepub_password,
    "HOST": os.environ.get("VINCE_PUB_DB_HOST", "localhost"),
    "PORT": os.environ.get("VINCE_PUB_DB_PORT", 5432),
}

if VINCE_NAMESPACE == "vincepub":
    # don't enable the admin interface for kb
    ADMIN_ENABLED = False
    DATABASES["default"] = {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": vincepub_db,
        "USER": vincepub_user,
        "PASSWORD": vincepub_password,
        "HOST": os.environ.get("VINCE_PUB_DB_HOST", "localhost"),
        "PORT": os.environ.get("VINCE_PUB_DB_PORT", 5432),
    }


if VINCE_NAMESPACE == "vinny":
    SESSION_COOKIE_PATH = "/vince/comm"
    DATABASES["default"] = {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": vincecomm_db,
        "USER": vincecomm_user,
        "PASSWORD": vincecomm_password,
        "HOST": os.environ.get("VINCE_COMM_DB_HOST", "localhost"),
        "PORT": os.environ.get("VINCE_COMM_DB_PORT", 5432),
    }

# Each application has their own database, so we can set permissions
# for each application.  VINCEPub can only access "vincepub" database.
# VINCEComm can access "vinny" and "vincepub" databases.  VINCETrack
# app can access all databases. The "cogauth" application uses the
# "vinny" database since that handles auth for all user accounts
# Using multiple databases really complicates django sessions -
# as session keys are stored in each database. This makes it especially
# difficult to run a local install using Cognito - which is why there is some extra
# javascript magic with storing tokens in the browser to do authentication when
# switching between applications

DATABASE_ROUTERS = ["vince.dbrouter.BigVinceRouter"]

AUTHENTICATION_BACKENDS = [
    "cogauth.backend.CognitoAuthenticate",
]

# Cognito Settings - these can be found in the AWS Cognito Console.
# The user pool must be setup prior to deploying
COGNITO_USER_POOL_ID = os.environ.get("AWS_COGNITO_USER_POOL_ID")
COGNITO_APP_ID = os.environ.get("AWS_COGNITO_APP_ID")
COGNITO_REGION = os.environ.get("AWS_COGNITO_REGION")
BASE_URL = os.environ.get("BASE_URL")
if COGNITO_REGION:
    if LOCALSTACK:
        keys_url = f"http://cognito-idp.{COGNITO_REGION}.{BASE_URL}/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    else:
        keys_url = "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json".format(
            COGNITO_REGION, COGNITO_USER_POOL_ID
        )

    response = urllib.request.urlopen(keys_url)
    COGNITO_KEYS = json.loads(response.read())["keys"]

# the AWS_COGNITO_ADMIN_GROUP and COGNITO_VINCETRACK_GROUPS name(s)
# should match up with the Cognito Group name
# The COGNITO_ADMIN_GROUP is used to promote users to "staff" upon login
# which give them permission to access the django admin console.
COGNITO_ADMIN_GROUP = os.environ.get("AWS_COGNITO_ADMIN_GROUP", "Coordinator")
# the following 2 vars can be comma separated string if more than 1
# group/team should have access to Track
# anyone in the COGNITO_VINCETRACK_GROUPS will be put in a
# "vincetrack" local group
COGNITO_VINCETRACK_GROUPS = os.environ.get("AWS_COGNITO_VINCETRACK_GROUPS", default=COGNITO_ADMIN_GROUP)

# Any user in this group will automatically be promoted to superuser
# Choose wisely - ideally this should be a more select set than the
# VINCETrack group
COGNITO_SUPERUSER_GROUP = os.environ.get("AWS_COGNITO_SUPERUSER_GROUP", COGNITO_ADMIN_GROUP)

# COGNITO_LIMITED_ACCESS_GROUPS can be used to give special permission to views
# in VINCECOMM

COGNITO_LIMITED_ACCESS_GROUPS = os.environ.get("AWS_COGNITO_LTD_ACCESS", default="Limited")

# If an account exists in AWS, but not locally - create the user locally
COGNITO_CREATE_UNKNOWN_USERS = True

COGNITO_ATTR_MAPPING = {
    "email": "email",
    "given_name": "first_name",
    "family_name": "last_name",
    "custom:Organization": "org",
    "locale": "country",
    "custom:title": "title",
    "preferred_username": "preferred_username",
    "custom:api_key": "api_key",
    "zoneinfo": "timezone",
}

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

if "AWS_ACCESS_KEY_ID" in os.environ:
    AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
    AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]

# Internationalization
# https://docs.djangoproject.com/en/2.1/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.1/howto/static-files/

MEDIA_URL = "/media/"

MEDIA_ROOT = BASE_DIR + "/media/"

DEFAULT_USER_SETTINGS = {
    "use_email_as_submitter": True,
    "email_on_ticket_assign": True,
    "email_on_ticket_change": True,
    "login_view_ticketlist": True,
    "tickets_per_page": 25,
}

# from emails on auto-notifications
DEFAULT_FROM_EMAIL = os.environ.get("NO_REPLY_EMAIL", "vuls+donotreply@vince.example")
# from for emails sent from VINCE
DEFAULT_REPLY_EMAIL = os.environ.get("REPLY_EMAIL", "vuls@vince.example")

# EMAIL_BUCKET = os.environ.get('S3_EMAIL_BUCKET', 'vince-email')

# if set to True, subjects of emails will only be compared with the queue names associated
# with the S3 bucket the email came from
TEAM_SPECIFIC_EMAIL_QUEUE = False

DEFAULT_VISIBLE_NAME = "VINCE"

# will set the reply to header in email - this must be set.
DEFAULT_REPLY_TO_EMAIL = DEFAULT_FROM_EMAIL

# default email headers, must be defined but could be an empty dictionary
DEFAULT_EMAIL_HEADERS = {"X-VINCE": "auto-notify"}

VINCE_MAX_EMAIL_LENGTH = 300000

IGNORE_EMAILS_TO = ["vuls+donotreply@vince.example"]

LOGLEVEL = os.environ.get("LOGLEVEL", "info").upper()
DJANGO_LOGLEVEL = os.environ.get("DJANGO_LOGLEVEL", "info").upper()
LOGGING_CONFIG = None

logging_dict = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "console": {
            # exact format is not important, this is the minimum information
            "format": "%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "console",
        },
    },
    "loggers": {
        # root logger
        "vince": {
            "level": LOGLEVEL,
            "handlers": [LOGGER_HANDLER],
        },
        "vinny": {
            "level": LOGLEVEL,
            "handlers": [LOGGER_HANDLER],
        },
        "cogauth": {
            "level": LOGLEVEL,
            "handlers": [LOGGER_HANDLER],
        },
        "django": {
            "level": DJANGO_LOGLEVEL,
            "handlers": [LOGGER_HANDLER],
        },
        "vincepub": {
            "level": LOGLEVEL,
            "handlers": [LOGGER_HANDLER],
        },
    },
}

if AWS_DEPLOYED and not LOCALSTACK:
    LOG_GROUP_NAME = os.environ.get("VINCE_LOG_GROUP_NAME", "VINCE")
    logging_dict["handlers"]["watchtower"] = {
        "level": "DEBUG",
        "class": "watchtower.CloudWatchLogHandler",
        "log_group": LOG_GROUP_NAME,
        "stream_name": VINCE_NAMESPACE,
        "formatter": "console",
    }

IS_WORKER = os.environ.get("IS_ELASTICBEANSTALK_WORKER", False)
IS_VINCEWORKER = os.environ.get("IS_VINCEWORKER", False)
if IS_VINCEWORKER and AWS_DEPLOYED and not LOCALSTACK:
    IS_VINCEWORKER = True
    INSTALLED_APPS.append("vinceworker")
    logging_dict["loggers"]["vinceworker"] = {
        "level": LOGLEVEL,
        "handlers": [LOGGER_HANDLER],
    }
    logging_dict["handlers"]["watchtower"]["stream_name"] = "vinceworker"

IS_KBWORKER = os.environ.get("IS_KBWORKER", False)
if IS_KBWORKER and AWS_DEPLOYED and not LOCALSTACK:
    IS_KBWORKER = True
    INSTALLED_APPS.append("kbworker")
    logging_dict["loggers"]["kbworker"] = {
        "level": LOGLEVEL,
        "handlers": [LOGGER_HANDLER],
    }
    logging_dict["handlers"]["watchtower"]["stream_name"] = "kbworker"
    # only need to define this for the worker

IS_VCWORKER = os.environ.get("IS_VCWORKER", False)
if IS_VCWORKER and AWS_DEPLOYED and not LOCALSTACK:
    IS_VCWORKER = True
    INSTALLED_APPS.append("vincecommworker")
    logging_dict["loggers"]["vincecommworker"] = {
        "level": LOGLEVEL,
        "handlers": [LOGGER_HANDLER],
    }
    logging_dict["handlers"]["watchtower"]["stream_name"] = "vcworker"

logging.config.dictConfig(logging_dict)

# LOGGING = logging_dict

STANDARD_VENDOR_EMAIL = "We have new information about a vulnerability \
that may affect your products. Please login to the VINCE portal for more information about this vulnerability."
STANDARD_PARTICIPANT_EMAIL = "Hello, VINCE coordinators invite you to participate in an active vulnerability disclosure case. \
Please login to the VINCE portal for more information about this case."


DEFAULT_PHONE_NUMBER = "412-268-5800"
# the default email signature in VINCE automatic notifications - make team specific in Team Settings
# used in Email Templates
DEFAULT_EMAIL_SIGNATURE = "The VINCE Vulnerability Coordination Team"

# This is used in form views as default text for email/contact forms
STANDARD_EMAIL_SIGNATURE = "\r\n\r\n\r\n\r\n\r\nRegards,\r\n\r\nVulnerability Analysis Team\r\n\
=====================================\r\n\
VINCE\r\n\
vince.yourdomain.com\r\n\
=====================================\r\n"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "cogauth.backend.HashedTokenAuthentication",
        #'rest_framework.authentication.TokenAuthentication',
        #        'cogauth.backend.JSONWebTokenAuthentication',
    ]
}

# 2.5MB - 2621440
# 5MB - 5242880
# 10MB - 10485760
# 20MB - 20971520
# 50MB - 5242880
# 100MB 104857600
# 250MB - 214958080
# 500MB - 429916160

MAX_UPLOAD_SIZE = 10485760

# if DEBUG == False:
#    CSRF_COOKIE_SECURE=True
#    SESSION_ENGINE='django.contrib.sessions.backends.signed_cookies'
##Designating the CSRF cookie as HttpOnly doesn’t offer any practical
# protection because CSRF is only to protect against cross-domain attacks.
# If an attacker can read the cookie via JavaScript, they’re already
# on the same domain as far as the browser knows,
# so they can do anything they like anyway. (XSS is a much bigger hole than CSRF.)
# If you enable this and need to send the value of the CSRF token with an AJAX request,
# your JavaScript must pull the value from a hidden CSRF token form input
# on the page instead of from the cookie.

CSRF_COOKIE_HTTPONLY = False

# Set CSRF trusted origins to our generated list of trusted domains
CSRF_TRUSTED_ORIGINS = [f"http://{t_domain}" for t_domain in trusted_domains] + [
    f"https://{t_domain}" for t_domain in trusted_domains
]

CSRF_FAILURE_VIEW = "vinny.views.csrf_failure_view"

# TEMPLATE SETTINGS

VINCEPUB_URL = os.environ.get("VINCE_PUB_DOMAIN")
VINCETRACK_URL = os.environ.get("VINCE_TRACK_DOMAIN")
VINCECOMM_URL = os.environ.get("VINCE_PUB_DOMAIN")

FAVICON = "vincepub/images/favicon.ico"

WEB_TITLE = "Vulnerability Notes Database"
ORG_NAME = "Your Organization Name"
CONTACT_EMAIL = "vuls@vince.example"
CONTACT_PHONE = "+12021115555"
ORG_POLICY_URL = "https://vuls.vince.example/terms"
ORG_AUTHORITY = f"{ORG_NAME} "
VINCEPUB_BASE_TEMPLATE = "vincepub/base_public.html"
VINCECOMM_BASE_TEMPLATE = "vinny/base_public.html"
VINCETRACK_BASE_TEMPLATE = "vince/base_public.html"
ACK_EMAIL_TEMPLATE = "vincepub/email-general.txt"

CASE_IDENTIFIER = "CASE#"
REPORT_IDENTIFIER = "REPORT#"

# CSAF API legal disclaimer
LEGAL_DISCLAIMER = """THIS DOCUMENT IS PROVIDED ON AN 'AS IS' BASIS AND DOES NOT IMPLY ANY KIND OF GUARANTEE OR WARRANTY, INCLUDING THE WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR USE. YOUR USE OF THE INFORMATION ON THE DOCUMENT OR MATERIALS LINKED FROM THE DOCUMENT IS AT YOUR OWN RISK. """


# allowed options: "prod", "test", "dev"
CVE_SERVICES_API = os.environ.get("CVE_SERVICES_API", "test")

# Django 3 and 4 upgrade
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# TLP related statements Note TLP2.0 says WHITE is replaced by CLEAR BUT CSAF2.0 is in TLP1.0
# https://github.com/oasis-tcs/csaf/issues/591
CSAF_DISTRIBUTION_OPTIONS = {
    "RED": {
        "distribution": {
            "text": "For the eyes and ears of individual recipients only, no further disclosure.",
            "tlp": {"label": "RED", "url": "https://www.first.org/tlp/"},
        }
    },
    "AMBER": {
        "distribution": {
            "text": "Limited disclosure, recipients can only spread this on a need-to-know basis within their organization and its clients.",
            "tlp": {"label": "AMBER", "url": "https://www.first.org/tlp/"},
        }
    },
    "GREEN": {
        "distribution": {
            "text": "Limited disclosure, recipients can spread this within their community.",
            "tlp": {"label": "GREEN", "url": "https://www.first.org/tlp/"},
        }
    },
    "WHITE": {
        "distribution": {
            "text": "Recipients can spread this to the world, there is no limit on disclosure. ",
            "tlp": {"label": "WHITE", "url": "https://www.first.org/tlp/"},
        }
    },
}
# Choose how VINCE's private and public CSAF documents are mapped with TLP
# If you choose to disable TLP statements in CSAF comment out the MAP dictionary below
CSAF_TLP_MAP = {"PUBLIC": "WHITE", "PRIVATE": "AMBER"}


# Choose alternate method to validate Session Tokens for non-AWS tokens
# and for writing Tests with mock sessions
def ALT_VERIFY_TOKEN(user, session):
    """
    This verify_token method provides an alternate way to verify Session
    Tokens for writing Tests with mock sessions. Add your alternate method
    if preferred to help with automated tests.
    """
    return False


# Added in SECTORS for VERSION 2.0.8
SECTORS = (
    ("Chemical", "Chemical"),
    ("Commercial Facilities", "Commercial Facilities"),
    ("Communications", "Communications"),
    ("Critical Manufacturing", "Critical Manufacturing"),
    ("Dams", "Dams"),
    ("Defense Industrial Base", "Defense Industrial Base"),
    ("Emergency Services", "Emergency Services"),
    ("Energy", "Energy"),
    ("Financial", "Financial"),
    ("Food and Agriculture", "Food and Agriculture"),
    ("Government Facilities", "Government Facilities"),
    ("Healthcare and Public Health", "Healthcare and Public Health"),
    ("Information Technology", "Information Technology"),
    ("Nuclear Reactors, Materials, and Waste", "Nuclear Reactors, Materials, and Waste"),
    ("Transportation Systems", "Transportation Systems"),
    ("Water and Wastewater Systems", "Water and Wastewater Systems"),
)
