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
* VINCE User Documentation: [https://vuls.cert.org/confluence/display/VIN/VINCE+Documentation](https://vuls.cert.org/confluence/display/VIN/VINCE+Documentation)
* Vulnerability Note API Documentation: [https://vuls.cert.org/confluence/display/VIN/Vulnerability+Note+API](https://vuls.cert.org/confluence/display/VIN/Vulnerability+Note+API)
* VINCE API Documentation: [https://vuls.cert.org/confluence/display/VIN/VINCE+API](https://vuls.cert.org/confluence/display/VIN/VINCE+API)

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


### Local Install

1. Clone the repo

2. Create a virtual environment and install requirements
```
cd bigvince
mkvirtualenv --python=/usr/local/bin/python3.6 bigvince  (python3 -m venv env)
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
python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
```
Swap out any "$" characters if they exist. $ characters mess with API key generation.  Or continue to regenerate until you get a key without a "$"
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

See docs for full AWS configuration