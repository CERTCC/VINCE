Installation Instructions
==========================

Local install instructions can be found in the README file.  This instruction guide is for installing VINCE in AWS. There are several pre-installation AWS configuration requirements.

Set up a development environment
---------------------------------

```
git clone [vince-github-repo]

python3 -m venv env

source env/bin/activate

pip install -r requirements

```

Create IAM user in AWS with programmatic access. Add keys to ~/.aws/config:

       [profile devtest]
       region=us-east-1
       aws_access_key_id = XXXXXX
       aws_secret_access_key = XXXXX!@#$

```
eb init --profile devtest
```

Google reCAPTCHA
-----------------

reCAPTCHA is used on a couple of the VINCE forms (vulnerability reporting form and VINCE registration page.) VINCE uses the v2 Invisible reCAPTCHA type.  Register a new site by adding the domains and selecting the appropriate reCAPTCHA type (reCAPTCHA v2).  You may need to add "localhost" if you will be testing locally.

Cognito User Pool
------------------

Using the AWS console, create a Cognito User Pool with the name "vince".  Choose to step through the settings to configure your new user pool:

* How do you want your end users to sign in?
  - Choose "Email Address" and "allow email addresses"
  - Enable case insensitivity for username input (This is a newer feature that VINCE 1.0 could not take advantage of)
* Which standard attributes are required
  - Preferred username
* Do you want to add custom attributes? YES, make sure all are "mutable", and min length 1, max noted below
  - Organization (512 characters)
  - first_name (256 characters)
  - last_name (256 characters)
  - title (256 characters)
  - api_key (256 characters)
* Password requirements: defaults are sufficient
  - allow user to sign themselves up.
* Do you want to enable multi-factor authentication?
  - Choose "OPTIONAL"
    * This is important, because otherwise it makes the signup/login process difficult and also makes it challenging to change MFA type.  The MFA requirement is enforced in the VINCE application
  - Choose both SMS and TOTP
* How will a user be able to recover their account?
  - Option 1: Email if available, otherwise phone, but don’t allow a user to reset their password via phone if they are also using it for MFA
* Which attributes do you want to verify?
  - Email
* You must provide a role to allow Amazon Cognito to send SMS messages
  - vince-SMS-role (auto-provided)

* Message customizations:
  - At this point, no email is setup, so you can't choose a FROM email address but once you setup SES, you will need to choose the email address you configure.  You'll also want to select "YES" to send emails through SES.

  - Customize email verification message:
    - Code
    - Email Subject: Your VINCE verification code
    - Email Message: Your VINCE verification code is {}
  - Do you want to customizer your user invitation messages?
    - Your VINCE username is {} and temporary password is {}
    - Email Subject: Your temporary password for VINCE

* Add app client
  - app client name: vince
  - Make sure you uncheck "Generate client secret"
  - Use Auth Flows Configuration defaults: ALLOW_CUSTOM_AUTH, ALLOW_USER_SRP_AUTH, ALLOW_REFRESH_TOKEN_AUTH
  - Security Configuration: prevent user existence errors: Enabled
  - Set attributes read and write permissions:
    - make sure all attributes are readable and writable

* Create a GROUP:
  - Group name must match whatever the "cognito_admin_group" environment variable is set to.


SNS
----------

Create 4 "Standard" Topics. Default options are fine.
Names:

* vince-email (Display name: VINCE)
* vince-email-bounce (Display name: VINCE Email Bounce)
* vince-pub
* vince-pub-errors

S3 Buckets
------------

Some S3 buckets will be created for you with cdk, but these 3 buckets must be created prior to deployment. Names can be customized but will need to be provided in environment variables:

* deployment bucket (e.g. vince-deploy-123) 
* artifacts bucket (e.g. vince-artifacts-123)
* email bucket (e.g. vince-email-123)

Add the following bucket policy for the email bucket. Replace aws:Referer "xx123442223xx" with your account number:

    {
	"Version": "2012-10-17",
    	"Statement": [
        	     {
            	     "Sid": "AllowSESPuts",
            	     "Effect": "Allow",
            	     "Principal": {
                          "Service": "ses.amazonaws.com"
            	     },
            	     "Action": "s3:PutObject",
            	     "Resource": "arn:aws:s3:::vince-email-a123/*",
            	     "Condition": {
                     		  "StringEquals": {
				                       "aws:Referer": "xx123442223xx"
                     				  }    
            	     		  }
        	     }
    		     ]
	}		     


SES
-----

Add your domain in SES
Create receipt rule in email receiving
Add email address: vince@yourdomain.com
Add S3 action:
S3 bucket: use email-bucket name from above
SNS Topic: use SNS email topic from above
Rule name: vince-rule-1
Review and Create Rule: The bucket policy must be configured above or it will fail to write to the bucket.
Optionally you can create IP address filters to only allow receiving email from particular IPs.

Add MX record in ROUTE 53: 10 inbound-smtp.us-east-1.amazonaws.com

Setup outgoing VINCE email:

Once the MX record has been added, you can verify an email address.

Add email address "vince@yourdomain.com" under Email addresses.  AWS will send a verification which you'll have to retrieve from the S3 bucket.  Download the file and copy/paste the link to verify the address.


Additional Configuration after Deployment
------------------------

ALLOWED_HOSTS in bigvince/settings.py must contain the domain you are deploying to otherwise you'll see "Bad Request" when going to the new VINCE URL.

You will have to create a new user using the regular VINCE Signup method. This user will be "pending."

Once the user is created, in the AWS Cognito Console, you can add your user to the Group you made earlier.  Logout the user and sign in again.  This user will now be able to see the VINCE Dashboard.

Create a superuser
------------------

Select Secret Manager in AWS console:

find vincerdsmaster:

copy secret value: XXXXX

Select RDS in AWS console:

Get RDS VINCE Endpoint: lsjfdlsjflsd.us-east-1.rds.amazonaws.com

Select EC2 in AWS console find bigvince-bastion:

Retrieve public ipv4 dns:

ec2-39493/compute-1.amazonaws.com

SSH into the bastion:

then you have access to the database - use the endpoint from above and the secret password for the database:

```
psql -h lsjfdlsjflsd.us-east-1.rds.amazonaws.com -p 5432 -U postgres -W

\c vincecord

UPDATE auth_user set is_superuser=true where id=2;

\c vincetrack

UPDATE auth_user set is_superuser=true where id=2;
```












      
  



