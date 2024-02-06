Configuration
==================

Environment Variables
---------------------

VINCE requires many environment variables to be set before running. This section explains the required variables.  If running locally, you can set these variables in bigvince/.env. Otherwise, they should be set in cdk/context/bigvince-prod.yaml.  The names in parenthesis are the variable names in the cdk context file.

Required
----------

* SECRET_KEY (django_secret_key): Django requires this variable to be set as it is used for hashing and signing data. You can use `python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'` to generate a new secret key
* VINCE_DEV_SYSTEM (vince_dev_banner): Set to 1 to display the "development system" banner and to use basic Django Email backend (not SES)
* GOOGLE_SITE_KEY (google_site_key): Generate a reCAPTCHA site and secret key to use with the forms
* GOOGLE_RECAPTCHA_SECRET_KEY (google_recaptcha_secret_key): generated with the site key
* SERVER_NAME (kb_cloudfront_domain_name, vince_cloudfront_domain_name) this is used when generating links in automated email
* VINCE_TRACK_DOMAIN (vince_cloudfront_domain_name)
* VINCE_COMM_DOMAIN (kb_cloudfront_domain_name)
* VINCE_PUB_DOMAIN (kb_cloudfront_domain_name)
* AWS_DEPLOYED (set if running in AWS)
* AWS_REGION region where services are deployed
* AWS_STORAGE_BUCKET_NAME the name of the bucket used for static content
* AWS_S3_REGION_NAME should be the same as AWS_REGION
* AWS_S3_CUSTOM_DOMAIN typically the SERVER_NAME
* AWS_LOCATION the top level folder in the AWS_STORAGE_BUCKET_NAME
* S3_INCOMING_REPORTS S3 bucket name (auto-generated) for incoming vulnerability notes
* S3_UPDATE_BUCKET_NAME S3 bucket name (auto-generated).  Used when publishing vulnerability notes
* S3_KB_SHARED_BUCKET_NAME the name of the S3 bucket used for vul notes
* AWS_COGNITO_APP_ID app ID for Cognito user pool
* AWS_COGNITO_ADMIN_GROUP the name of the Cognito group that, if available, will promote users to "staff members" which gives them access to the Admin interface
* AWS_COGNITO_SUPERUSER_GROUP the name of the Cognito group that, if available, will promote users to "superuser" which gives them access to the Admin interface, delete capability, as well as additional view access.
* AWS_COGNITO_REGION the region where the Cognito user pool is configured
* AWS_COGNITO_USER_POOL_ID the ID for the Cognito user pool
* AWS_SECRET_MANAGER set to True to use secret manager
* LOGLEVEL (DEBUG, INFO, WARNING)
* NO_REPLY_EMAIL the FROM email address for automatic VINCE notifications
* REPLY_EMAIL the FROM email address for VINCE manually-generated emails
* PRIVATE_BUCKET_NAME the name of the S3 bucket that will be used for file storage
* S3_EMAIL_BUCKET the name of the S3 bucket that is configured to receive email from SES
* VINCE_COMM_AUTH the arn to the secret manager
* VINCE_COMM_DB_HOST the hostname of the RDS instance
* VINCE_COMM_DB_PORT the port for the RDS instance (5432)
* VINCE_TRACK_AUTH the arn to the secret manager
* VINCE_TRACK_DB_HOST the hostname of the RDS instance
* VINCE_TRACK_DB_PORT the port for the RDS instance (5432)
* VINCE_PUB_AUTH the arn to the secret manager
* VINCE_PUB_DB_HOST the hostname of the RDS instance
* VINCE_PUB_DB_PORT the port for the RDS instance (5432)
* VINCE_NAMESPACE (vince, vinny, or vincepub) depending on which instance is running
* VINCE_LOG_GROUP_NAME cloudwatch name for VINCE logging
* VINCE_ERROR_SNS_ARN the SNS arn that VINCE errors are published to. Team email should be subscribed to this queue to receive any critical errors or misconfigurations
* VINCE_SHARED_BUCKET_NAME the name of the "private" S3 bucket for VINCEComm. VINCETrack needs access to this to move information back and forth
* VINCE_SUPERUSER_AUTH the arn for the secret manager that holds superuser credentials
* VINCE_TRACK_SNS_ARN the SNS arn that the vinceworker is subscribed to

settings.py variables
--------------


* DEBUG (should never be set on a production system)
* DEFAULT_TIME_ZONE
* MULTIURL_CONFIG This should be set if you plan to run the different VINCE applications on different domains. We chose to do this so we could setup Web ACLs in Cloudfront on the VINCETrack app. This configuration is used by the MultipleDomainMiddleware that forces Django to redirect to the correct domain depending on the URL requested. If the entire application is running under 1 domain, this should be set to False.
* BAKERY_FILESYSTEM due to the read-only nature of elasticbeanstalk instances, this must be set to "mem://"
* ALLOWED_HOSTS must contain the host/domain name that this site can serve.
* STATIC_URL the URL to use when referring to static files located in STATIC_ROOT
* STATIC_ROOT the absolute path to the directory where static files will collect for deployment - this does not need to be set for local deployments but should be set if using bakery to generate HTML files.
* STANDARD_VENDOR_EMAIL the default email to use when notifying vendors of new cases
* STANDARD_PARTICIPANT_EMAIL the default email to use when notifying potential participants of new cases
* DEFAULT_PHONE_NUMBER the default phone number to use in the footer of email notifications
* DEFAULT_EMAIL_SIGNATURE the default email signature using in automatic VINCE notifications
* STANDARD_EMAIL_SIGNATURE this is the default email signature for non-automatic VINCE notifications
* COGNITO_VINCETRACK_GROUPS these are Cognito groups that should be put into the VINCE "vincetrack" group in VINCEComm and the "vince" group in VINCETrack.
* COGNITO_LIMITED_ACCESS_GROUPS these are the Cognito group names that have access to particular views in VINCEComm
* COGNITO_ATTR_MAPPING this is the mapping from Cognito to the VINCE User and VinceProfile models.  If additional information is needed for the user account, the mapping should be expanded to include those fields.
* DEFAULT_FROM_EMAIL the default email to send VINCE notifications from
* DEFAULT_REPLY_EMAIL the default email to send non-automatic VINCE notifications from
* DEFAULT_VISIBLE_NAME the name to use with emails
* DEFAULT_REPLY_TO_EMAIL the default email to use in the "reply-to" header in email
* DEFAULT_EMAIL_HEADERS additional email headers to set on outgoing VINCE email
* IGNORE_EMAILS_TO the list of email addresses that VINCE shall ignore if email received in VINCE are sent TO the list
* IS_WORKER set to True to enable VINCE worker URLs and code
* IS_VINCEWORKER set to True to enable VINCE Track worker URLS and code
* IS_KBWORKER set to True to enable VINCEPub worker URLS and code
* IS_VCWORKER set to True to enable VINCEComm worker URLs and code
* VINCE_MAX_EMAIL_LENGTH the maximum bytes of an email that VINCE will append to a ticket


VINCE Configuration
---------------------

Before you can use VINCE, you must do some basic configuration.  Most of this can be done via the Django admin views.

1. Visit ``http://vince.yoursite.com/vince/create/contact/`` and add 1 contact for each of your coordination team(s)
2. Visit ``http://vince.yoursite.com/admin/`` and add a Group(s). The required "vince" group has already been added if you ran the command loadinitialdata. Anyone that should have access to VINCETrack will belong in the "vince" group.  The additional groups that you add should be the names of the coordination teams that will be working in VINCE and will determine access to queues, tickets, etc.  Under Group Settings, choose the Contact you added in step 1.  Decide if this team should have certain permissions such as:

* Publish - the ability to publish vulnerability notes
* Contact Read - the ability to read Contact information (this can be changed at the user level, but will be the default for a user when they are added to this team.)
* Contact Write - the ability to write/edit Contact information (this can be changed at the user level, but will be the default for a user when they are added to this team.)

3. Visit ``http://vince.yoursite.com/admin/`` and add Ticket Queues. Some ticket queues have already been added.  If you choose to use the provided queues, you must add edit each queue and add permissions for the group you created in step 2 to read/write/publish. Ideally you should add at least 3 ticket queues (1 of each type) for each team.  Define the team owner for each ticket queue and add permissions for each team that should have access to the quque. Optionally, provide the s3 bucket name for incoming email. Email that originates from this bucket will create a ticket on this queue.

Queue Types
---------------

* General Ticket
* Case Task Queue
* Case Request Queue

In each ticket queue, you have to grant r/w permissions to the appropriate team(s).  If you don't plan to create more than 1 team, you can grant permission to the "vince" group to allow universal r/w on the ticket queues.






