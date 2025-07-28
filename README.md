## VINCE 

### Description

VINCE - The Vulnerability Information and Coordination Environment - Software
designed for multi-party vulnerability coordination.  VINCE enables
collaborative and efficient coordination by allowing all involved parties to
tap into a central, web-based platform to communicate directly with one
another about a vulnerability.  It is based on the decades of experience with
coordinated vulnerability disclosure (CVD) at the CERT Coordination Center
(CERT/CC) which is a part of the Software Engineering Institute at Carnegie
Mellon University.

* The CERT Guide to Coordinated Vulnerability Disclosure: [https://vuls.cert.org/confluence/display/CVD](https://vuls.cert.org/confluence/display/CVD)
* Report a Vulnerability [https://www.kb.cert.org/vuls/report/](https://www.kb.cert.org/vuls/report/)
* VINCE User Documentation: [https://certcc.github.io/VINCE-docs/](https://certcc.github.io/VINCE-docs/)
* Vulnerability Note API Documentation: [https://certcc.github.io/VINCE-docs/Vulnerability-Note-API/](https://certcc.github.io/VINCE-docs/Vulnerability-Note-API/)
* VINCE API Documentation: [https://certcc.github.io/VINCE-docs/VINCE-API/](https://certcc.github.io/VINCE-docs/VINCE-API/)

### Bugs and Feature Requests

You can report a bug, feature request, or other issue in this GitHub project. VINCE users can also send [feedback](https://kb.cert.org/vince/comm/sendmsg/8/) through the Private Message feature.

### About

VINCE, a Django application, is designed to run in Amazon Web Services (AWS)
and is developed around many
of AWS services such as Cognito, S3, ElasticBeanstalk, Cloudfront, SQS, SNS,
and SES. VINCE uses the python library,
[warrant](https://github.com/capless/warrant), for AWS Cognito
authentication.  [Warrant](https://github.com/capless/warrant) has been
slightly modified and is included with VINCE. 

VINCE also uses and includes
the [django-bakery](https://github.com/palewire/django-bakery) project to
generate and publish flat HTML files of vulnerability notes that are served
via an AWS S3 bucket. The
[django-bakery](https://github.com/palewire/django-bakery) project has been
modified to generate the flat files in memory versus using the filesystem. 

VINCE also has a [development](https://github.com/CERTCC/VINCE/tree/development)
branch which can be run using [LocalStack](https://localstack.cloud).


### Architecture

VINCE follows a traditional Django's `Model-Template-View-Controller` for most part.
VINCE's 3-Tier setup is designed to work with Web/Presentation Tier (Amazon CloudFront),
Application Tier (Amazon ElasticBeanStalk) and Database Tier (Amazon RDS).  All these
components can be mimicked (or replaced) to either use LocalStack or individual
open-source software for each of these tiers. VINCE's services interface to Storage (Amazon S3)
Notifications (Amazon SNS), Queueing (Amazon SQS) and Messaging (Amazon SES) are all modular
and can be adapted to either LocalStack or other python3+Django supported modules. VINCE's
Identity Management is defaulted to Cognito - this also can be modified to use other Identity
Providers. Cognito identity is also tied to few modules such as S3 buckets used for file
storage, including both uploads and downloads. These can be mimicked using LocalStack. Code
updates may be required in cases of file interactions. 

VINCE application is made of three individual applications and databases.
* VINCETRACK application (database vincetrack) launched from (vince/)[vince/] folder.
* VINCECOMM application (database vincecomm) launched from (vinny/)[vinny/].
* VINCEPUB application (database vincepub) launched from (vincepub/)[vincepub/].

The VINCETRACK application requires access to all three database schemas and tables.
The VINCETRACK app is meant for `Coordinators and Administrators` by default deisgned to be in
a group labeled as `Coordinator` or as setup in `bigvince.settings.COGNITO_ADMIN_GROUP`
with higher privileges. The VINCECOMM and VINCEPUB applications have access to their respective schemas.
The VINCECOMM applications is acessible to Vendors, Finders
(Security Researchers) as well as other stakeholders that are registered, verified and have been approved. The
VINCEPUB application provides publicly available publications and reports that unauthenticated
users. Each application can also be further protected by network access controls as desired to
reduce the risk of exposure.

[<img src="https://github.com/CERTCC/VINCE/raw/main/Vince_Infrastructure.png" width="100%"></A>](https://github.com/CERTCC/VINCE/raw/main/Vince_Infrastructure.png)


### Local Install

1. Clone the repo

2. Create a virtual environment and install requirements
```
cd bigvince
mkvirtualenv  bigvince 
source env/bin/activate
pip install -r requirements.txt
```

3. Create a postgres database using docker
```
docker run --name bv-postgres -p 5432:5432 -e POSTGRES_PASSWORD=PASSWORD -d postgres
createdb -h localhost -U postgres bigvince
```

3. Alternate (not using docker):
```
psql postgres
CREATE ROLE vince;
ALTER ROLE vince CREATEDB;
ALTER ROLE "vince" WITH LOGIN;
CREATE DATABASE vincetest;
GRANT ALL PRIVILEGES ON DATABASE vincetest TO vince;
CREATE DATABASE vincecommtest;
GRANT ALL PRIVILEGES ON DATABASE vincecommtest TO vince;
CREATE DATABASE vincepubtest;
GRANT ALL PRIVILEGES ON DATABASE vincepubtest TO vince;
```

4. Edit and copy VINCE.env to bigvince\.env with the environment variables needed to run VINCE locally - this includes the database connection string and password for the new database, AWS keys, Google reCAPTCHA keys, etc.
```
DATABASE_URL=postgres://postgres@127.0.0.1:5432/bigvince
DATABASE_PASSWORD=PASSWORD
```

5. Create secret key
```
python3 -c 'from django.utils.crypto import get_random_string; chars = "abcdefghijklmnopqrstuvwxyz0123456789!@#%^&*(-_=+)"; print(get_random_string(50, chars));';
```
Add it to bigvince/.env

6. Edit bigvince/settings_.py as needed with your settings. Important settings to pay attention to:

```
EMAIL_BACKEND
BUILD_DIR
DEFAULT_FROM_EMAIL
DEFAULT_REPLY_EMAIL
DEFAULT_VISIBLE_NAME
STANDARD_VENDOR_EMAIL
STANDARD_PARTICIPANT_EMAIL
DEFAULT_PHONE_NUMBER
DEFAULT_EMAIL_SIGNATURE
STANDARD_EMAIL_SIGNATURE
WEB_TITLE
ORG_NAME
CONTACT_EMAIL
*_BASE_TEMPLATES
REPORT_IDENTIFIER
CASE_IDENTIFIER
SUPERUSER

```

7. Run migrations
```
python manage.py makemigrations
python manage.py migrate
python manage.py migrate --database=vincecomm
python manage.py migrate --database=vincepub
```

8. Create a django super user. This will be used to login into the application.


It uses the credentials defined in the settings.py SUPERUSER variable. Alternatively
you can use Django's createsuperuser command to set your own username and password.

NOTE: Skip this step if using cognito auth (the default)
``` 
python manage.py createsu
```

9. Load initial data:
```
python manage.py loadinitialdata
```

10. Start the development server. (Profit)
```
python manage.py runserver 
```

11. Attempt login
12. Set "is_superuser" to "true" for your user in vincecomm and vincetrack databases, auth_user relation.

## Running tests

Vince test are stored in vince/tests. To run tests:

```
python3 manage.py test vince
```

This will create a new database for the tests and will delete it when the tests completes. To speed up tests, you can tell Django to not delete the test DB.

```
python3 manage.py test vince -k
```

## Fresh deployment reminders

Remember to give the "vince" group access to all of the Ticket Queues in admin console.

### AWS Install

See docs for [full AWS configuration](./doc/aws-install.md)