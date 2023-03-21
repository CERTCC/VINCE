## Localstack installation
### Dependencies
First install:
- [Docker](https://get.docker.com/)
- [Docker-Compose](https://docs.docker.com/compose/install/)
- git

Then clone down this repository and `cd` into it.
Run the following:
`git checkout development`

### Configuration
Then acquire a valid [Localstack](https://localstack.cloud/) Pro license key (trial will work)

Environment Variables:
#### VINCE/.env:
- Modify the `LOCALSTACK_API_KEY` variable to be proper API key.

#### VINCE/bigvince/.env:
- Modify the `SECRET_KEY` variable if desired. This is accomplished by running the following command from a python environment that has django installed:
```
python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
```

Add the following to `/etc/hosts`. An example line is below:

    127.0.0.1   localstack
    127.0.0.1   testpool.us-east-1.localstack

An example `.env` for usage under `bigvince` is provided with fake or development only values. Although it must be copied to the proper location

#### Copy settings_.py
`bigvince/settings_.py` will need to be copied to `bigvince/settings.py`


#### Windows Specific
- Modify Dockerfile-dev to use 20.04.
- Set `git config --global core.autocrlf input` before cloning the repository.

### Usage
Run `sudo docker-compose up`, and wait 2-5 minutes

Navigate to `http://localstack`

### Additional commands
Commands of note are below:
- `docker-compose rm` (remove existing "down" containers)
- `docker-compose logs` (show logs for all containers)
- `docker-compose build` (rebuild vince base container)
- `docker-compose up -d` (run in the background)
- `docker-compose ps` (show status of containers)
- `docker-compose exec <name_of_container> /bin/bash` (start a bash shell in a running container)

## Additional notes
- The default password is currently set in the fixtures, it can be modified after logging in for the first time
- The ADMIN_EMAIL field is used for login, not the username
- If the containers are created anew from stratch then the browser cache will need to be cleared to remove an old JWT token
- Multiurl is currently disabled
- MFA is currently disabled
- The default google recaptcha keys already present will always return "valid" as they are for development purposes
- Storage ACLs are disabled
- This is for development purposes only, do not run in production.
