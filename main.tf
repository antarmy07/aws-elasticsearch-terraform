provider "aws" {
  region = "<your-aws-region>"
}


terraform {
  backend "s3" {
    bucket = "<your-tf-files-backend-bucket>"
    dynamodb_table = "<your-tf-files-backend-dynamodb-table"
    encrypt = true
    key = "<your-s3-bucket-object>"
    region = "<your-aws-region>"
  }
}

/* data source 
*************************************************************************************************************
*/
data "aws_vpc" "selected" {
  cidr_block = "<your-aws-vpc-cidr>"
}

data "aws_subnet_ids" "A" {
  vpc_id = "${data.aws_vpc.selected.id}"
  tags = {
    Name = "IT-INF Private A"
  }
}

data "aws_subnet_ids" "B" {
  vpc_id = "${data.aws_vpc.selected.id}"
  tags = {
    Name = "IT-INF Private B"
  }
}

data "aws_caller_identity" "current" {}


data "aws_region" "current" {}

variable "domain" {
  default = "contoso-es"
}

data "aws_iam_role" "contoso-congnito-role" {
  name = "CognitoAccessForAmazonES"
}
data "aws_iam_role" "contoso-eks-worker-node-role" {
  name = "IT-INF-EKS-NODE-ROLE"
}

/* es security group 
*************************************************************************************************************
*/

resource "aws_security_group" "es" {
  name        = "IT-INF-ES-SG"
  description = "Managed by Terraform"
  vpc_id      = "${data.aws_vpc.selected.id}"

    ingress {
		from_port = 1
		to_port = 65535
		protocol = "tcp"
		cidr_blocks = ["<your onpremise IP address cidr>"]

	}
    ingress {
		from_port = 1
		to_port = 65535
		protocol = "tcp"
		cidr_blocks = ["<your-aws-vpc-cidr>"]

	}
    ingress {
		from_port = 1
		to_port = 65535
		protocol = "tcp"
		self = true

    }
  
	egress {
		from_port = 0
		to_port = 0
		protocol = "-1"
		cidr_blocks = ["0.0.0.0/0"]
	}
    
}


/* amazon cognito user pool
*************************************************************************************************************
*/

resource "aws_cognito_user_pool_domain" "contoso-congnito-user-pool" {
  domain       = "contoso"
  user_pool_id = "${aws_cognito_user_pool.contoso-congnito-user-pool.id}"
}

resource "aws_cognito_user_pool" "contoso-congnito-user-pool" {
  name = "IT-INF-USER-POOL"
}

/* amazon cognito frederated identity pool
*************************************************************************************************************
*/

resource "aws_cognito_identity_pool" "contoso-congnito-identity-pool" {
  identity_pool_name               = "kibana"
  allow_unauthenticated_identities = true
}


/* amazon cognito frederated identity pool role attachement
*************************************************************************************************************
*/

resource "aws_iam_role" "contoso-congnito-identity-poolauthenticated-role" {
  name = "IT-INF-cognito-authenticated-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.contoso-congnito-identity-pool.id}"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "contoso-congnito-identity-poolauthenticated-policy" {
  name = "authenticated_policy"
  role = "${aws_iam_role.contoso-congnito-identity-poolauthenticated-role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "mobileanalytics:PutEvents",
        "cognito-sync:*",
        "cognito-identity:*"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
EOF
}

resource "aws_cognito_identity_pool_roles_attachment" "main" {
  identity_pool_id = "${aws_cognito_identity_pool.contoso-congnito-identity-pool.id}"

   roles = {
    "authenticated" = "${aws_iam_role.contoso-congnito-identity-poolauthenticated-role.arn}"
  }

}

/* amazon elasticsearch domain
*************************************************************************************************************
*/

resource "aws_elasticsearch_domain" "contoso-elk-domain" {
  domain_name           = "${var.domain}"
  elasticsearch_version = "6.7"

  cluster_config {  
    instance_type = "t2.small.elasticsearch" #your choice of EC2 
    instance_count = 2
    zone_awareness_enabled = true
    zone_awareness_config {
    availability_zone_count = 2
    }
  }

  vpc_options {
  subnet_ids = [
      "${data.aws_subnet_ids.A.ids[0]}",
      "${data.aws_subnet_ids.B.ids[0]}", ]


    security_group_ids = ["${aws_security_group.es.id}"]
  }

  advanced_options = {
    "rest.action.multi.allow_explicit_index" = "true"
  }
  
  access_policies = <<CONFIG
  {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
        "${aws_iam_role.contoso-congnito-identity-pooauthenticated-role.arn}",
        "${data.aws_iam_role.contoso-eks-worker-node-role.arn}"
        ]
      },
      "Action": "es:*",
      "Resource": "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.domain}/*"
    }
  ]
}
CONFIG

  snapshot_options {
    automated_snapshot_start_hour = 23
  }

  ebs_options{
        ebs_enabled = true
        volume_size = 50
    }

  cognito_options {
    enabled = true
    user_pool_id = "${aws_cognito_user_pool.contoso-congnito-user-pool.id}"
    identity_pool_id = "${aws_cognito_identity_pool.contoso-congnito-identity-pool.id}"
    role_arn = "${data.aws_iam_role.contoso-congnito-role.arn}"
  }

  tags = {
    Domain = "contoso-es"
  }
  depends_on = [ 
    "aws_cognito_user_pool.contoso-congnito-user-pool", "aws_cognito_identity_pool.contoso-congnito-identity-pool", 
   ]
}

/* amazon single sign on
*************************************************************************************************************
*/

locals {
  aws_sso_config = <<CONFIGAWSSSO

Go to website below and Configuring AWS Single Sign-On

https://aws.amazon.com/blogs/security/how-to-enable-secure-access-to-kibana-using-aws-single-sign-on/ 


***From AWS SSO Dashboard, select Applications and then Add a new application. Select Add a custom SAML 2.0 application.*** 

***To allow AWS SSO to support IdP initiated flow please add Application start URL by copying kinbana endpoint URL here  ****

***Unders Application metadata. Select the link that reads If you don’t have a metadata file, you can manually type your metadata values.***

Enter this on ACS URL = https://contoso.auth.<your-aws-region>.amazoncognito.com/saml2/idpresponse
Enter this on SAML audience = urn:amazon:cognito:sp:${aws_cognito_user_pool.contoso-congnito-user-pool.id}

***Under Attribute mappings tab and next to Subject***

Enter mapping according to the guide

***Under Assigned users***

Select the security group that will be allowed to access Kibana

CONFIGAWSSSO
}
output "aws_sso_config" {
  value = "${local.aws_sso_config}"
}