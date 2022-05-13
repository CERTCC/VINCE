

## Setup 

### Fresh Setup (No AWS CDK, no virtualenv)
#### 1. Install V2 AWS CLI - https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html
AWS CLI V2 is now installed as a software package. See URL above to get the right one. 

#### 2. Install Cloud Development Kit - https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html
Node is needed for the installation. For Macs, the Homebrew version of Node seems to work fine.

#### 3. Create a new python virtualenv
*NOTE*: Python 3.7 seems to be minimum, newer versions should work. Caveat emptor.

```bash
# If using virtualenv-wrappers:
$ mkvirtualenv --python /path/to/your/python3 aws-cdk 

# If using vanilla virtualenv:
$ virtualenv -p /path/to/your/python3 aws-cdk
```

#### 4. Activate virtualenv
*NOTE*: virtualenv-wrappers should have done this for you. 

```bash
# If using vanilla virtualenv:
$ . aws-cdk/bin/activate
```

#### 5. Install base python requirements

```bash
(aws-cdk) $ pip install -r requirements.txt
```


### Existing Setup
#### 1. Activate Virtualenv
(installation dependent)
#### 2. Update Node.js CDK Package
```bash
(aws-cdk) $ npm install -g aws-cdk
```
#### 3. Update Python CDK Core Module
```bash
(aws-cdk) $ pip install --upgrade aws-cdk.core
```
#### 4. Update Python Dependencies
```bash
(aws-cdk) $ pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip install -U
```

## Deployment

### Update context  

#### 1. Copy context/example-context.yaml to &lt;new-stack&gt;.yaml

#### 2. Update all fields with :update:

#### 3. Copy cdk.json.template to cdk.json

#### 4. Update cdk.json to point it at the new context file created in #1.
```json
{
    "app": "python3 app.py",
     "context": {
       "yaml_context": "context/<new-stack>.yaml"
     }
}
```

#### 5. Update lambda/AddSecurityHeaders/app.py to reflect your chosen hostnames for the cloudfront endpoints (look for :update:).

### Configure AWS Account Info for helper calls
Various helper functions utilize boto3 for id lookups and the like. boto3 will 
happily use your default AWS credentials from ~/.aws/. This could lead to 
hard-to-trace failures where ids from the wrong account are inserted into the 
templates. 

If using profiles configured in ~/.aws/, set the `AWS_PROFILE` envvar to the
name of the profile to use for all AWS cli and boto3 actions. 

Alternatively, set the envvars for `AWS_ACCESS_KEY_ID` and 
`AWS_SECRET_ACCESS_KEY` as needed.

### Deploy 

#### i. Preconfigure: Bootstrap CDK
If this is a fresh account, the account will need to bootstrap CDK:
```bash

cdk bootstrap aws://<account_id>/<region>

```
#### ii. Preconfigure: Add SSH keys to EC2
If this is a fresh account, add/create an SSH key pair in EC2, and add the
reference to the context config file.

#### iii. Preconfigure: Build the deploy zipfile and upload to S3
Reference the `deploy-*` scripts in the source tree `scripts` directory. If
this is a fresh deployment, generate the initial deployment zipfile and
upload to S3. Set the bucket and zipfile names in the context config file
when finished. 

#### 1. Create CloudFront certificates

*NOTE*: If you are using an imported certificate, skip creating this stack.

```bash 

cdk deploy <stack-name>-cf-certs 

```

#### 2. Create CloudFront Edge Lambda

The kb and vince CloudFront distributions use LambdaEdge functions to add security headers to site traffic.  kb also uses LambdaEdge to rewrite traffic bound for static vulnerability indexes.
These functions need to be created in us-east-1 to work with LambdaEdge.  

To create LambdaEdge functions:

```bash

cdk deploy <stack-name>-lambdaedge

```  

#### 3. Deploy vince and kb

```bash

cdk deploy <stack-name>-vince-eb <stack-name>-kb-eb <stack-name>-vincecomm-eb

```

### Potential Issues
#### Several (possibly all) EB services show "Degraded"
If logs show that there were failures in migration steps, especially related to databases not existing, try first to
restart all of the affected EB instances. There appears to be a race condition during deployment that can result in
the services starting in an order where the databases needed are not initialized when the migration steps are
called. Restarting the instances will cause the migrations to run again, hopefully correctly. 

#### Some EB worker processes show "Degraded"
Log examination might show that `sqsd` was unable to start, or appears to be in a restart loop. Closer examination of
logs on the EB instances themselves using `journalctl -xe` might show an error like this: 
```
Jan 28 19:39:56 ip-[redacted].ec2.internal sqsd[27292]: /opt/elasticbeanstalk/lib/ruby/lib/ruby/gems/2.6.0/gems/aws-sqsd-3.0.3/bin/aws-sqsd:58:in `initialize': No such file or directory @ rb_sysopen - /var/run/aws-sqsd/default.pid (Errno::ENOENT)
```
Upon further investigation, we found that, for reasons that are unclear at this point, the /var/run/aws-sqsd directory 
was not created. To fix, use the bastion to connect to the EC2 instance for the affected worker, then:
```bash
mkdir /var/run/aws-sqsd
chgrp sqsd /var/run/aws-sqsd
chmod 775 /var/run/aws-sqsd
systemctl restart sqsd
```
Note: You will have to either elevate to root, or prepend each of those with `sudo`. Your choice. We won't judge.


### Destroy

Destroy is a complicated mess.

#### 1. Delete any buckets created.

```bash

/bin/bash scripts/delete-buckets.sh <stack-name>

```
Be aware that this may inquire about buckets created in the buckets stack. Maybe don't delete those here.

#### 2. Delete RDS databases

```bash

python3 scripts/delete-rds.py -r <region_name> <vince-rds-stack-name>

```

#### 3. Delete the following stacks:

```bash

cdk destroy <stack-name>-secrets <stack-name>-certs <stack-name>-cloudfront <stack-name>-vpc <stack-name>-buckets <stack-name>-logging

```

#### 4. Delete the CloudFront certificates

```bash

cdk destroy <stack-name>-cf-certs

```

#### 5. After the CloudFront stack is deleted, you will need to wait up to a few hours before deleting the lambdaedge stack. 
This is because these lambda functions are replicated across CloudFront edge locations and cannot
be deleted until all references to the functions are removed.  This can take a while.  

See: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-edge-delete-replicas.html

After AWS unreplicates itself:

```bash

cdk destroy <stack-name>-lambdaedge

```

#### 6. Remove the Cloudwatch log group, if appropriate
The <stack-name>-logging log group in Cloudwatch will remain after the logging stack is deleted, according
  to the log retention settings for the group. If appropriate, manually remove the log group from within
  the console.
  
 There is a helper script `scripts/delete-logs.py` that will help to find and remove log groups by stack prefix:
 
 ```bash

python3 scripts/delete-logs.py -r <region_name> <stack_prefix>
 
```
 


