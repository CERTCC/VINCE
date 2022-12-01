## Localstack installation
### Dependencies
First install:
- [Docker](https://get.docker.com/)
- [Docker-Compose](https://docs.docker.com/compose/install/)
- git

Then clone down this repository and `cd` into it.

### Configuration
Then acquire a valid [Localstack](https://localstack.cloud/) Pro license key (trial will work)

Modify the `LOCALSTACK_API_KEY variable` in `.env` to be proper API key.

Add `testbucket.s3.us-east-1.localstack` and `localstack` to `/etc/hosts`. An example line is below:

    127.0.1.1   testbucket.s3.us-east-1.localstack
    127.0.2.1   localstack


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
- Multiurl is currently disabled
- MFA is currently disabled
- The default google recaptcha keys already present will always return "valid" as they are for development purposes
- Storage ACLs are disabled
- This is for development purposes only, do not run in production.