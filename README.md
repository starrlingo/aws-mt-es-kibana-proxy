# AWS Multi-tenancy ES/Kibana Proxy
This proxy inspired from [santthosh/aws-es-kibana](https://github.com/santthosh/aws-es-kibana). The enhanced features are descripted as following.
## Features
* Providing AWS Elasticsearch and Kibana as a service in **multi-tenancy** mode.
* Providing user **authentication** for requesting AWS Elasticsearch & Kibana by BasicAuth.
* Providing user **authorization** by assuming AWS IAM roles.
* Providing **index/report/dashboard level isolation** at the UI level for different users in Kibana.
* Providing access log in Cloudwatch logs.

## Installation
1. Install AWS CLI (This step can be skipped if you are in Amazon Linux AMI)

  ~~~
  curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
  unzip awscli-bundle.zip
  sudo ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
  ~~~
2. Configure AWS Credential (This step can be skipped if you runs in AWS EC2 environment and associated EC2 with IAM role)

  Place the credentials in a file at ~/.aws/credentials based on the following template:

  ~~~
  [default]
  aws_access_key_id = <your_access_key_id>
  aws_secret_access_key = <your_secret_access_key>
  ~~~
Note: For security concern, it's not recommended to setup AWS credential in local. 
You should launch an EC2 instance (associated with IAM role) to access another AWS services.

3. Setting up your policy in IAM user or role
  ~~~
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": [
                  "sts:AssumeRole",
                  "logs:*"
              ],
              "Resource": "*"
          }
      ]
  }
  ~~~
4. Git clone

  ~~~
  git clone https://github.com/starrlingo/aws-mt-es-kibana-proxy.git
  cd aws-mt-es-kibana-proxy
  npm install
  ~~~

## Configuration
1. Create IAM role for each of your login user or tenantId

  The proxy will try to assume target role with userId (default) or tenantId after passing the authentication check.
  This IAM role will define which index can access or which http method are allowed to perform. 

  Create your role policy as following.

  IAM Role Name: `<proxy-name>-<userId>` or `<proxy-name>-<tenantId>`

  IAM Role Policy:
  ~~~
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": "es:*",
              "Resource": [
                  "<domain ARN>/",
                  "<domain ARN>/favicon.ico",
                  "<domain ARN>/_plugin/kibana",
                  "<domain ARN>/_plugin/kibana/*",
                  "<domain ARN>/_nodes",
                  "<domain ARN>/_nodes/*",
                  "<domain ARN>/.kibana-4",
                  "<domain ARN>/.kibana-4-easontest",
                  "<domain ARN>/.kibana-4-easontest/*",
                  .......Insert any policy you want here.....
              ]
          }
      ]
  }
  ~~~
2. Grant the permission in access policy of AWS Elasticsearch service for each of your login user or tenantId

  Click "Modify access policy" to add the following policy
  ~~~
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<your account id>:role/<your iam role name>"
      },
      "Action": "es:*",
      "Resource": "arn:aws:es:<region>:<your account id>:domain/<your es domain name>/"
    }
  ~~~
3. Customize your own authentication code

  The sample authentication code is in `lib/exampleLocalAuth.js` (Authenticate in local) and `lib/exampleApiAuth.js` (Authienticate by API). This class defined a static method called authenticate to verify the user's identity.

  You can customize it to what authentication detail you like. For example, encrypt your password in MD5 or call external authenticate API with customized header.

  * User and TenantId mapping
    Different user may share the same tenancy. For example, Jason and John are both share the same tenancy from following example mapping.

    ~~~
    Jason: {
      password: '1234'
      tenantId: 'dep01
    },
    John: {
      password: '5678'
      tenantId: 'dep01
    },
    Mary: {
      password: '9012'
      tenantId: 'dep02
    }
    ~~~
Note: If there are no tenantId returned in the callback of authenticate function, proxy will assume the role with userId instead.

## Usage
Run the proxy

    node index.js <cluster-endpoint> -a <auth-classname> -b <bind-address> -n <proxy-name> -p <port> -r <es-region>
~~~
<cluster-endpoint>: visit AWS Elasticsearch console to get the endpoint URL.
-a <auth-classname> (optional): the name of authentication class. Default value is exampleLocalAuth.
-b <bind-address> (optional): the IP address to bind to. Default value is 127.0.0.1.
-n <proxy-name> (optional): the name of proxy. Default value is aws-mt-kibana.
-p <port> (optional): the port to bind to. Default value is 80.
-r <es-region> (optional): the region of the Elasticsearch domain.
~~~

Watch the access logs
* Visit the AWS Cloudwatch logs console in the same region with AWS Elasticsearch.
* Find access logs in Log Groups: es-kibana-proxy-access-log/<proxy-name>
