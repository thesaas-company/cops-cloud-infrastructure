import os

from awacs.aws import (
    Action,
    Allow,
    Condition,
    PolicyDocument,
    Principal,
    Statement,
    StringEqualsIfExists,
    StringLikeIfExists
)
from awacs.sts import AssumeRole
from troposphere import Ref, Sub, Template, GetAtt, Parameter
from troposphere.iam import ManagedPolicy, PolicyType, Role, Policy
from troposphere.sqs import Queue, QueuePolicy
from troposphere.events import Rule


from troposphere.cloudformation import AWSCustomObject

COPS_CONDITION = Condition(
    StringEqualsIfExists(
        "aws:RequestTag/ManagedByCops",
        "true",
    )
)

# Description for the reader IAM role CloudFormation template
READER_CF_DESCRIPTION = (
    "Cops Reader CloudFormation Template: "
    "This CloudFormation template is used to create a reader IAM role for Cops. The role's "
    "primary purpose is "
    "to grant read-only access to Cops resources. By using this role, users will have the "
    "ability to view and "
    "retrieve information from Cops resources while maintaining strict restrictions on "
    "modifying or altering them. "
)

# Description for the updater IAM role CloudFormation template
UPDATER_CF_DESCRIPTION = (
    "Cops Management CloudFormation Template: "
    "This CloudFormation template is responsible for creating a management IAM role that Cops "
    "will utilize. "
    "This role is intended for management purposes and does not grant permissions for creating, "
    "deleting, tagging, "
    "or untagging resources. Its purpose is to provide necessary access for efficiently managing "
    "Cops resources."
)

# Description for the provisioner IAM role CloudFormation template
PROVISIONER_CF_DESCRIPTION = (
    "Cops Provisioner CloudFormation Template: "
    "This CloudFormation template is designed to create an admin IAM role specifically for "
    "Cops to trust. The "
    "purpose of this role is to enable Cops to provision the infrastructure required for "
    "its operations."
)

KARPENTER_CF_DESCRIPTION= (
    "Cops Karpenter CloudFormation Template: "
    "This CloudFormation template is designed to create an admin IAM role specifically for "
    "eks cluster to trust. The "
    "purpose of this role is to enable karpenter"
)


def create_read_policy(role_type):
    """
    Create a managed policy for the reader IAM role.
    :return: The ManagedPolicy object.
    """
    return ManagedPolicy(
        "CopsReaderPermission",
        ManagedPolicyName=f"reader-policy-for-{role_type}-role",
        PolicyDocument=PolicyDocument(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("logs", "DescribeLogGroups"),
                        Action("logs", "DescribeLogStreams"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:cops-*"
                        ),
                        Sub(
                            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group::log-stream*"
                        ),
                        Sub(
                            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/eks/cops-*:*"
                        ),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("logs", "ListTagsLogGroup"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:cops-*"
                        ),
                        Sub(
                            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group::log-stream*"
                        ),
                        Sub(
                            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/eks/cops-*:*"
                        ),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("s3", "ListBucket"),
                        Action("s3", "GetEncryptionConfiguration"),
                        Action("s3", "GetBucketLogging"),
                        Action("S3", "GetBucketPolicy"),
                        Action("s3", "GetAccelerateConfiguration"),
                        Action("s3", "GetBucketAcl"),
                        Action("s3", "GetBucketWebsite"),
                        Action("s3", "GetBucketVersioning"),
                        Action("s3", "ListBucketVersions"),
                        Action("s3", "GetBucketCORS"),
                        Action("s3", "GetBucketLocation"),
                        Action("s3", "GetReplicationConfiguration"),
                        Action("s3", "GetBucketTagging"),
                        Action("s3", "GetBucketOwnershipControls"),
                        Action("s3", "GetBucketRequestPayment"),
                        Action("s3", "GetLifecycleConfiguration"),
                        Action("s3", "GetObject"),
                        Action("s3", "GetBucketObjectLockConfiguration"),
                        Action("s3", "GetBucketPublicAccessBlock"),
                    ],
                    Resource=[
                        "arn:aws:s3:::cops-*",
                        "arn:aws:s3:::cops-*/*",
                        "arn:aws:s3:::cops-*",
                        "arn:aws:s3:::cops-*/*",
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("events", "DescribeRule"),
                        Action("events", "ListTargetsByRule"),
                        Action("events", "ListTagsForResource"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:events:${AWS::Region}:${AWS::AccountId}:rule/Karpenter*"
                        )
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("sqs", "GetQueueAttributes"),
                        Action("sqs", "ListQueueTags"),
                    ],
                    Resource=[
                        Sub("arn:aws:sqs:${AWS::Region}:${AWS::AccountId}:Karpenter*")
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("autoscaling", "DescribeAutoScalingGroups"),
                        Action("autoscaling", "DescribeScalingActivities"),
                        Action("autoscaling", "DescribeTags"),
                    ],
                    Resource=["*"],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("eks", "DescribeCluster"),
                        Action("eks", "DescribeNodegroup"),
                        Action("eks", "DescribeUpdate"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:cluster/cops-*"
                        ),
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:nodegroup/cops-*/cops-*/*"
                        ),
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:nodegroup/cops-*"
                        ),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("eks", "ListTagsForResource"),
                        Action("eks", "ListNodegroups"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:cluster/cops-*"
                        ),
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:nodegroup/cops-*/cops-*/*"
                        ),
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:nodegroup/cops-*"
                        ),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("kms", "GetKeyPolicy"),
                        Action("kms", "GetKeyRotationStatus"),
                        Action("kms", "DescribeKey"),
                    ],
                    Resource=[
                        Sub("arn:aws:kms:${AWS::Region}:${AWS::AccountId}:alias/*"),
                        Sub("arn:aws:kms:${AWS::Region}:${AWS::AccountId}:key/*"),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("kms", "ListResourceTags"),
                        Action("kms", "ListAliases"),
                    ],
                    Resource=["*"],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("iam", "GetOpenIDConnectProvider"),
                        Action("iam", "GetInstanceProfile"),
                    ],
                    Resource=[
                        Sub("arn:aws:iam::${AWS::AccountId}:oidc-provider/*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:instance-profile/*"),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("iam", "GetPolicyVersion"),
                        Action("iam", "GetPolicy"),
                        Action("iam", "GetRole"),
                        Action("iam", "GetRolePolicy"),
                        Action("iam", "ListPolicyVersions"),
                        Action("iam", "ListPolicyTags"),
                        Action("iam", "ListRoleTags"),
                        Action("iam", "ListInstanceProfilesForRole"),
                        Action("iam", "ListRolePolicies"),
                        Action("iam", "ListAttachedRolePolicies"),
                    ],
                    Resource=[
                        Sub("arn:aws:iam::${AWS::AccountId}:policy/cops-*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:policy/Cops-*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:policy/*fluentbitrole*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:policy/*fluentbitpolicy*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:role/*AWSService*"),
                        Sub(
                            "arn:aws:iam::${AWS::AccountId}:role/aws-service-role/*.amazonaws.com/*"
                        ),
                        Sub("arn:aws:iam::${AWS::AccountId}:role/cops-*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:role/Cops-*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:role/*fluentbitrole*"),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("iam", "ListOpenIDConnectProviderTags"),
                        Action("iam", "ListInstanceProfileTags"),
                    ],
                    Resource=[
                        Sub("arn:aws:iam::${AWS::AccountId}:oidc-provider/*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:instance-profile/*"),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("ec2", "DescribeVpcAttribute"),
                    ],
                    Resource=["*"],
                    Condition=COPS_CONDITION,
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("ec2", "DescribeAccountAttributes"),
                        Action("ec2", "DescribeAddresses"),
                        Action("ec2", "DescribeAvailabilityZones"),
                        Action("ec2", "DescribeFlowLogs"),
                        Action("ec2", "DescribeInstanceTypeOfferings"),
                        Action("ec2", "DescribeInternetGateways"),
                        Action("ec2", "DescribeNatGateways"),
                        Action("ec2", "DescribeNetworkAcls"),
                        Action("ec2", "DescribeNetworkInterfaces"),
                        Action("ec2", "DescribePrefixLists"),
                        Action("ec2", "DescribeRouteTables"),
                        Action("ec2", "DescribeSecurityGroupRules"),
                        Action("ec2", "DescribeSecurityGroups"),
                        Action("ec2", "DescribeSubnets"),
                        Action("ec2", "DescribeVpcAttribute"),
                        Action("ec2", "DescribeVpcClassicLink"),
                        Action("ec2", "DescribeVpcClassicLinkDnsSupport"),
                        Action("ec2", "DescribeVpcEndpoints"),
                        Action("ec2", "DescribeVpcs"),
                        Action("ec2", "DescribeImages"),
                        Action("ec2", "DescribeLaunchTemplates"),
                        Action("ec2", "DescribeLaunchTemplateVersions"),
                        Action("ec2", "GetEbsEncryptionByDefault"),
                        Action("iam", "ListRoles"),
                        Action("iam", "ListPolicies"),
                    ],
                    Resource=["*"],
                ),
            ],
        ),
    )


def create_updater_policy(role_type):
    """
    Create a managed policy for the updater IAM role.
    :return: The ManagedPolicy object.
    """
    return ManagedPolicy(
        "CopsUpdaterPermission",
        ManagedPolicyName=f"updater-policy-for-{role_type}-role",
        PolicyDocument=PolicyDocument(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("ec2", "ModifyVpcAttribute"),
                        Action("ec2", "ModifyVpcEndpoint"),
                        Action("ec2", "ModifySubnetAttribute"),
                        Action("ec2", "ModifyLaunchTemplate"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:vpc-endpoint/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:internet-gateway/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:elastic-ip/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:natgateway/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:route-table/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:subnet/subnet-*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:security-group-rule/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:security-group/*"
                        ),
                        Sub("arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:subnet/*"),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:vpc-flow-log/*"
                        ),
                        Sub("arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:vpc/*"),
                    ],
                    Condition=COPS_CONDITION,
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("eks", "UpdateNodegroupConfig"),
                        Action("eks", "UpdateNodegroupVersion"),
                        Action("eks", "UpdateClusterConfig"),
                        Action("eks", "UpdateClusterVersion"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:cluster/cops-*"
                        ),
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:nodegroup/cops-*/cops-*/*"
                        ),
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:nodegroup/cops-*"
                        ),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("autoscaling", "UpdateAutoScalingGroup"),
                        Action("autoscaling", "CreateOrUpdateTags"),
                        Action("autoscaling", "DeleteTags"),
                    ],
                    Resource=["*"],
                    Condition=COPS_CONDITION,
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("eks", "CreateNodegroup"),
                        Action("eks", "TagResource"),
                        Action("eks", "UntagResource"),
                        Action("eks", "DeleteNodegroup"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:cluster/cops-*"
                        ),
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:nodegroup/cops-*/cops-*/*"
                        ),
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:nodegroup/cops-*"
                        ),
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:addon/cops-*/*/*"
                        ),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("eks", "CreateAddon"),
                        Action("eks", "UpdateAddon"),
                        Action("eks", "DeleteAddon"),
                        Action("eks", "DescribeAddonVersions"),
                        Action("eks", "DescribeAddon"),
                        Action("eks", "ListAddons"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:cluster/cops-*"
                        ),
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:addon/cops-*/*/*"
                        ),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("ec2", "CreateLaunchTemplate"),
                        Action("ec2", "CreateLaunchTemplateVersion"),
                        Action("ec2", "DeleteLaunchTemplate"),
                    ],
                    Resource=["*"],
                ),
            ],
        ),
    )


def create_provisioner_policy(role_type):
    """
    Create a managed policy for the provisioner IAM role.
    :return: The ManagedPolicy object.
    """
    return ManagedPolicy(
        "CopsProvisionerPermission",
        ManagedPolicyName=f"provisioner-policy-for-{role_type}-role",
        PolicyDocument=PolicyDocument(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("logs", "TagLogGroup"),
                        Action("logs", "DeleteLogGroup"),
                        Action("logs", "CreateLogGroup"),
                        Action("logs", "PutRetentionPolicy"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/eks/cops-*/cluster:log-stream"
                        ),
                        Sub(
                            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:cops-*"
                        ),
                        Sub(
                            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group::log-stream*"
                        ),
                        Sub(
                            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/eks/cops-*:*"
                        ),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("sqs", "CreateQueue"),
                        Action("sqs", "DeleteQueue"),
                        Action("sqs", "SetQueueAttributes"),
                        Action("sqs", "TagQueue"),
                        Action("sqs", "UntagQueue"),
                    ],
                    Resource=[
                        Sub("arn:aws:sqs:${AWS::Region}:${AWS::AccountId}:Karpenter*")
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("events", "DeleteRule"),
                        Action("events", "PutRule"),
                        Action("events", "PutTargets"),
                        Action("events", "RemoveTargets"),
                        Action("events", "TagResource"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:events:${AWS::Region}:${AWS::AccountId}:rule/Karpenter*"
                        )
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("ec2", "AllocateAddress"),
                        Action("ec2", "AttachInternetGateway"),
                        Action("ec2", "DetachInternetGateway"),
                        Action("ec2", "CreateInternetGateway"),
                        Action("ec2", "DeleteInternetGateway"),
                        Action("ec2", "CreateNatGateway"),
                        Action("ec2", "DeleteNatGateway"),
                        Action("ec2", "CreateRoute"),
                        Action("ec2", "DeleteRoute"),
                        Action("ec2", "CreateRouteTable"),
                        Action("ec2", "DeleteRouteTable"),
                        Action("ec2", "DisassociateRouteTable"),
                        Action("ec2", "AuthorizeSecurityGroupEgress"),
                        Action("ec2", "AuthorizeSecurityGroupIngress"),
                        Action("ec2", "RevokeSecurityGroupIngress"),
                        Action("ec2", "AuthorizeSecurityGroupEgress"),
                        Action("ec2", "CreateSecurityGroup"),
                        Action("ec2", "RevokeSecurityGroupEgress"),
                        Action("ec2", "DeleteSubnet"),
                        Action("ec2", "CreateNatGateway"),
                        Action("ec2", "CreateSubnet"),
                        Action("ec2", "DeleteFlowLogs"),
                        Action("ec2", "CreateFlowLogs"),
                        Action("ec2", "CreateVpc"),
                        Action("ec2", "AssociateVpcCidrBlock"),
                        Action("ec2", "ReleaseAddress"),
                        Action("ec2", "CreateTags"),
                        Action("ec2", "RunInstances"),
                        Action("ec2", "DeleteTags"),
                        Action("ec2", "CreateLaunchTemplate"),
                        Action("ec2", "CreateLaunchTemplateVersion"),
                        Action("ec2", "CreateVpcEndpoint"),
                        Action("ec2", "AssociateAddress"),
                        Action("ec2", "DeleteVpc"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:vpc-endpoint/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:internet-gateway/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:elastic-ip/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:natgateway/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:route-table/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:subnet/subnet-*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:security-group-rule/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:security-group/*"
                        ),
                        Sub("arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:subnet/*"),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:vpc-flow-log/*"
                        ),
                        Sub("arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:vpc/*"),
                    ],
                    Condition=COPS_CONDITION,
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("ec2", "AssociateRouteTable"),
                        Action("ec2", "DeleteSecurityGroup"),
                        Action("ec2", "DeleteVpcEndpoints"),
                        Action("ec2", "DisassociateAddress"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:vpc-endpoint/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:internet-gateway/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:elastic-ip/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:natgateway/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:route-table/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:subnet/subnet-*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:security-group-rule/*"
                        ),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:security-group/*"
                        ),
                        Sub("arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:subnet/*"),
                        Sub(
                            "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:vpc-flow-log/*"
                        ),
                        Sub("arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:vpc/*"),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("eks", "DeleteCluster"),
                        Action("eks", "CreateCluster"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:eks:${AWS::Region}:${AWS::AccountId}:cluster/cops-*"
                        ),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("kms", "CreateAlias"),
                        Action("kms", "DeleteAlias"),
                        Action("kms", "EnableKeyRotation"),
                        Action("kms", "PutKeyPolicy"),
                        Action("kms", "ScheduleKeyDeletion"),
                        Action("kms", "TagResource"),
                        Action("kms", "UntagResource"),
                        Action("kms", "CreateGrant"),
                    ],
                    Resource=[
                        Sub("arn:aws:kms:${AWS::Region}:${AWS::AccountId}:alias/*"),
                        Sub("arn:aws:kms:${AWS::Region}:${AWS::AccountId}:key/*"),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("kms", "CreateKey"),
                    ],
                    Resource=["*"],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("iam", "DeleteOpenIDConnectProvider"),
                        Action("iam", "CreateOpenIDConnectProvider"),
                        Action("iam", "TagOpenIDConnectProvider"),
                        Action("iam", "UntagOpenIDConnectProvider"),
                        Action("iam", "CreateInstanceProfile"),
                        Action("iam", "RemoveRoleFromInstanceProfile"),
                        Action("iam", "DeleteInstanceProfile"),
                        Action("iam", "TagInstanceProfile"),
                        Action("iam", "UntagInstanceProfile"),
                        Action("iam", "AddRoleToInstanceProfile"),
                        Action("iam", "UpdateAssumeRolePolicy"),
                    ],
                    Resource=[
                        Sub("arn:aws:iam::${AWS::AccountId}:oidc-provider/*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:instance-profile/*"),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("iam", "CreatePolicy"),
                        Action("iam", "DeletePolicy"),
                        Action("iam", "TagPolicy"),
                        Action("iam", "UntagPolicy"),
                        Action("iam", "TagRole"),
                        Action("iam", "UntagRole"),
                        Action("iam", "CreateRole"),
                        Action("iam", "DeleteRole"),
                        Action("iam", "AttachRolePolicy"),
                        Action("iam", "PutRolePolicy"),
                        Action("iam", "DetachRolePolicy"),
                        Action("iam", "DeleteRolePolicy"),
                        Action("iam", "CreatePolicyVersion"),
                        Action("iam", "DeletePolicyVersion"),
                    ],
                    Resource=[
                        Sub("arn:aws:iam::${AWS::AccountId}:policy/cops-*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:policy/Cops-*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:policy/*fluentbitrole*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:policy/*fluentbitpolicy*"),
                        
                        Sub("arn:aws:iam::${AWS::AccountId}:role/*AWSService*"),
                        Sub(
                            "arn:aws:iam::${AWS::AccountId}:role/aws-service-role/*.amazonaws.com/*"
                        ),
                        Sub("arn:aws:iam::${AWS::AccountId}:role/cops-*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:role/Cops-*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:role/*fluentbitrole*"),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("autoscaling", "CreateLaunchConfiguration"),
                        # Permissions necessary for Service Quota Checks (INFRA-3)
                        Action("ec2", "DescribeInstanceTypes"),
                        Action("servicequotas", "GetServiceQuota"),
                        Action("cloudwatch", "GetMetricStatistics"),
                    ],
                    Resource=["*"],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("autoscaling", "CreateAutoScalingGroup"),
                        Action("autoscaling", "DeleteAutoScalingGroup"),
                        Action("autoscaling", "SetInstanceProtection"),
                    ],
                    Resource=["*"],
                    Condition=COPS_CONDITION,
                ),
            ],
        ),
    )


def create_terraform_policy(role_type):
    """
    Create a managed policy for the admin IAM role used by Terraform.
    :return: The ManagedPolicy object.
    """
    return ManagedPolicy(
        "CopsTerraformPermission",
        ManagedPolicyName=f"terraform-policy-for-{role_type}-role",
        PolicyDocument=PolicyDocument(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("s3", "CreateBucket"),
                        Action("s3", "DeleteBucket"),
                        Action("s3", "PutEncryptionConfiguration"),
                        Action("s3", "DeleteBucketPolicy"),
                        Action("s3", "PutBucketPolicy"),
                        Action("s3", "PutBucketTagging"),
                        Action("s3", "PutObject"),
                        Action("s3", "DeleteObject"),
                        Action("s3", "PutBucketAcl"),
                        Action("s3", "PutObjectAcl"),
                        Action("s3", "PutBucketAcl"),
                        Action("s3", "PutBucketLogging"),
                        Action("s3", "PutBucketVersioning"),
                        Action("s3", "PutBucketCORS"),
                        Action("s3", "PutBucketLocation"),
                        Action("s3", "PutReplicationConfiguration"),
                        Action("s3", "PutBucketTagging"),
                        Action("s3", "PutBucketOwnershipControls"),
                        Action("s3", "PutBucketRequestPayment"),
                        Action("s3", "PutLifecycleConfiguration"),
                        Action("s3", "PutBucketObjectLockConfiguration"),
                        Action("s3", "PutBucketPublicAccessBlock"),
                        Action("s3", "DeleteObject"),
                        Action("s3", "DeleteObjectVersion"),
                    ],
                    Resource=[
                        "arn:aws:s3:::cops-*",
                        "arn:aws:s3:::cops-*/*",
                        "arn:aws:s3:::cops-*",
                        "arn:aws:s3:::cops-*/*",
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("iam", "CreateServiceLinkedRole"),
                        Action("iam", "PassRole"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:iam::${AWS::AccountId}:role/aws-service-role/*.amazonaws.com/*"
                        ),
                        Sub("arn:aws:iam::${AWS::AccountId}:role/cops-*"),
                        Sub("arn:aws:iam::${AWS::AccountId}:role/Cops-*"),
                    ],
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("ec2", "EnableEbsEncryptionByDefault"),
                        Action("ec2", "ModifyEbsDefaultKmsKeyId"),
                        Action("ec2", "DisableEbsEncryptionByDefault"),
                        Action("ec2", "GetEbsEncryptionByDefault"),
                    ],
                    Resource=["*"],
                    Condition=Condition(
                        StringEqualsIfExists("ec2:Region", Sub("${AWS::Region}"))
                    ),
                ),
                Statement(
                    Effect=Allow,
                    Action=[
                        Action("dynamodb", "DescribeTable"),
                        Action("dynamodb", "GetItem"),
                        Action("dynamodb", "PutItem"),
                        Action("dynamodb", "DeleteItem"),
                        Action("dynamodb", "CreateTable"),
                        Action("dynamodb", "DeleteTable"),
                    ],
                    Resource=[
                        Sub(
                            "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/cops-*"
                        )
                    ],
                ),
            ],
        ),
    )

def create_karpenter_policy(cluster_name):
    """
    Create a managed policy for the admin IAM role used by Terraform.
    :return: The ManagedPolicy object.
    """
    return ManagedPolicy(
        "KarpenterControllerPolicy",
        ManagedPolicyName=f"KarpenterControllerPolicy-${cluster_name}",
        PolicyDocument=PolicyDocument(
            Version="2012-10-17",
            Statement=[
                # Statement(
                #     Sid="AllowScopedEC2InstanceAccessActions",
                #     Effect=Allow,
                #     Action=[
                #         "ec2:RunInstances",
                #         "ec2:CreateFleet"
                #     ],
                #     Resource=[
                #         Sub("arn:${AWS::Partition}:ec2:${AWS::Region}::image/*"),
                #         Sub("arn:${AWS::Partition}:ec2:${AWS::Region}::snapshot/*"),
                #         Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:security-group/*"),
                #         Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:subnet/*")
                #     ]
                # ),
                Statement(
                    Sid="AllowScopedEC2LaunchTemplateAccessActions",
                    Effect=Allow,
                    Action=[
                        Action("ec2","CreateFleet"),
                        Action("ec2","RunInstances"),
                    ],
                    Resource=Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:launch-template/*"),
                    Condition=Condition(
                        #  StringEqualsIfExists(f"aws:ResourceTag/kubernetes.io/cluster/${cluster_name}",  "owned"),
                         StringLikeIfExists("aws:ResourceTag/karpenter.sh/nodepool",  "*")
                    )
                ),
                Statement(
                    Sid="AllowScopedEC2InstanceActionsWithTags",
                    Effect=Allow,
                    Action=[
                        "ec2:RunInstances",
                        "ec2:CreateFleet",
                        "ec2:CreateLaunchTemplate"
                    ],
                    Resource=[
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:fleet/*"),
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:instance/*"),
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:volume/*"),
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:network-interface/*"),
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:launch-template/*"),
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:spot-instances-request/*")
                    ],
                    Condition=[
                        Condition(
                         StringEqualsIfExists(f"aws:ResourceTag/kubernetes.io/cluster/${cluster_name}",  "owned"),
                         StringLikeIfExists( "aws:ResourceTag/karpenter.sh/nodepool",  "*")
                        ),
                        Condition(
                            StringEqualsIfExists(f"aws:ResourceTag/kubernetes.io/cluster/${cluster_name}",  "owned"),
                            StringLikeIfExists( "aws:ResourceTag/karpenter.sh/nodepool",  "*")
                        )
                    ]
                ),
                Statement(
                    Sid="AllowScopedResourceCreationTagging",
                    Effect=Allow,
                    Action="ec2:CreateTags",
                    Resource=[
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:fleet/*"),
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:instance/*"),
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:volume/*"),
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:network-interface/*"),
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:launch-template/*"),
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:spot-instances-request/*")
                    ],
                    Condition=Condition(
                         StringEqualsIfExists(f"aws:ResourceTag/kubernetes.io/cluster/${cluster_name}",  "owned"),
                         StringEqualsIfExists("ec2:CreateAction",  [
                                "RunInstances",
                                "CreateFleet",
                                "CreateLaunchTemplate"
                            ]),
                         StringLikeIfExists( "aws:ResourceTag/karpenter.sh/nodepool",  "*")
                    )
                 
                ),
                # Add other statements as needed
                Statement(
                    Sid="AllowScopedDeletion",
                    Effect=Allow,
                    Action=[
                        "ec2:TerminateInstances",
                        "ec2:DeleteLaunchTemplate"
                    ],
                    Resource=[
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:instance/*"),
                        Sub("arn:${AWS::Partition}:ec2:${AWS::Region}:*:launch-template/*")
                    ],
                    Condition=Condition(
                         StringEqualsIfExists(f"aws:ResourceTag/kubernetes.io/cluster/${cluster_name}",  "owned"),
                         StringLikeIfExists( "aws:ResourceTag/karpenter.sh/nodepool",  "*")
                    )
                ),
                Statement(
                    Sid="AllowRegionalReadActions",
                    Effect=Allow,
                    Action=[
                        "ec2:DescribeAvailabilityZones",
                        "ec2:DescribeImages",
                        "ec2:DescribeInstances",
                        "ec2:DescribeInstanceTypeOfferings",
                        "ec2:DescribeInstanceTypes",
                        "ec2:DescribeLaunchTemplates",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeSpotPriceHistory",
                        "ec2:DescribeSubnets"
                    ],
                    Resource="*",
                    Condition=Condition(

                         StringLikeIfExists( "aws:RequestedRegion", "${AWS::Region}")
                    )
                ),
                Statement(
                    Sid="AllowSSMReadActions",
                    Effect=Allow,
                    Action="ssm:GetParameter",
                    Resource=Sub("arn:${AWS::Partition}:ssm:${AWS::Region}::parameter/aws/service/*")
                ),
                Statement(
                    Sid="AllowPricingReadActions",
                    Effect=Allow,
                    Action="pricing:GetProducts",
                    Resource="*"
                ),
                # Add other read actions or specific permissions as needed
                Statement(
                    Sid="AllowInterruptionQueueActions",
                    Effect=Allow,
                    Action=[
                        "sqs:DeleteMessage",
                        "sqs:GetQueueUrl",
                        "sqs:ReceiveMessage"
                    ],
                    Resource=GetAtt("KarpenterInterruptionQueue", "Arn")
                ),
                Statement(
                    Sid="AllowPassingInstanceRole",
                    Effect=Allow,
                    Action="iam:PassRole",
                    Resource=GetAtt("KarpenterNodeRole", "Arn"),
                ),
                # Add other IAM statements as required
                Statement(
                    Sid="AllowScopedInstanceProfileCreationActions",
                    Effect=Allow,
                    Action=[
                        "iam:CreateInstanceProfile"
                    ],
                    Resource="*",
                    Condition=Condition(
                         StringEqualsIfExists(f"aws:ResourceTag/kubernetes.io/cluster/${cluster_name}",  "owned"),
                         StringLikeIfExists( "aws:ResourceTag/karpenter.sh/nodepool",  "*"),
                          StringLikeIfExists( "aws:RequestedRegion", "${AWS::Region}")
                    ),
                ),
                Statement(
                    Sid="AllowScopedInstanceProfileTagActions",
                    Effect=Allow,
                    Action=[
                        "iam:TagInstanceProfile"
                    ],
                    Resource="*",
                    Condition=Condition(
                         StringEqualsIfExists(f"aws:ResourceTag/kubernetes.io/cluster/${cluster_name}",  "owned"),
                         
                          StringEqualsIfExists( "aws:RequestTag/topology.kubernetes.io/region", "${AWS::Region}"),
                          StringLikeIfExists( "aws:ResourceTag/karpenter.k8s.aws/ec2nodeclass", "*")
                    )

                ),
                Statement(
                    Sid="AllowScopedInstanceProfileActions",
                    Effect=Allow,
                    Action=[
                        "iam:AddRoleToInstanceProfile",
                        "iam:RemoveRoleFromInstanceProfile",
                        "iam:DeleteInstanceProfile"
                    ],
                    Resource="*",
                    Condition=Condition(
                         StringEqualsIfExists(f"aws:ResourceTag/kubernetes.io/cluster/${cluster_name}",  "owned"),
                         
                          StringEqualsIfExists( "aws:RequestTag/topology.kubernetes.io/region", "${AWS::Region}"),
                          StringLikeIfExists( "aws:ResourceTag/karpenter.k8s.aws/ec2nodeclass", "*")
                    )

                ),
                Statement(
                    Sid="AllowIAMPassRole",
                    Effect=Allow,
                    Action="iam:PassRole",
                    Resource=GetAtt("KarpenterNodeRole", "Arn"),
                    Condition=Condition(
                         StringEqualsIfExists("iam:PassedToService",  "ec2.amazonaws.com"),
                    )

                )
            ]
        )
    )

def create_queue_policy(cluster_name):
    return Queue(
        "KarpenterInterruptionQueue",
        QueueName=Sub("${cluster_name}"),
        MessageRetentionPeriod=300,
        KmsMasterKeyId="kms_key",
        SqsManagedSseEnabled=True
    )


def create_interruption_policy():
    return QueuePolicy(
        "KarpenterInterruptionQueuePolicy",
        Queues=[Ref("KarpenterInterruptionQueue")],
        PolicyDocument={
            "Id": "EC2InterruptionPolicy",
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": ["events.amazonaws.com", "sqs.amazonaws.com"]},
                    "Action": "sqs:SendMessage",
                    "Resource": GetAtt("KarpenterInterruptionQueue", "Arn")
                }
            ]
        }
    )


def create_schedule_rule():
    return Rule(
        "ScheduledChangeRule",
        EventPattern={
            "source": ["aws.health"],
            "detail-type": ["AWS Health Event"]
        },
        Targets=[{
            "Id": "KarpenterInterruptionQueueTarget",
            "Arn": GetAtt("KarpenterInterruptionQueue", "Arn")
        }]
    )

def create_spot_rule():
    return Rule(
        "SpotInterruptionRule",
        EventPattern={
            "source": ["aws.ec2"],
            "detail-type": ["EC2 Spot Instance Interruption Warning"]
        },
        Targets=[{
            "Id": "KarpenterInterruptionQueueTarget",
            "Arn": GetAtt("KarpenterInterruptionQueue", "Arn")
        }]
    )

def create_rebalance_rule():
    return Rule(
        "RebalanceRule",
        EventPattern={
            "source": ["aws.ec2"],
            "detail-type": ["EC2 Instance Rebalance Recommendation"]
        },
        Targets=[{
            "Id": "KarpenterInterruptionQueueTarget",
            "Arn": GetAtt("KarpenterInterruptionQueue", "Arn")
        }]
    )


def create_statechange_rule():
    return Rule(
        "InstanceStateChangeRule",
        EventPattern={
            "source": ["aws.ec2"],
            "detail-type": ["EC2 Instance State-change Notification"]
        },
        Targets=[{
            "Id": "KarpenterInterruptionQueueTarget",
            "Arn": GetAtt("KarpenterInterruptionQueue", "Arn")
        }]
    )


def create_role(name, policy_arn):
    """
    Create a managed policy for the IAM role.
    :param name: The name of the IAM role.
    :param policy_arn: The list of policy ARNs.
    :return: The Role object.
    """
    return Role(
        "CrossAccountRoleForAWSTrustedAdvisorCops",
        RoleName=name,
        AssumeRolePolicyDocument=PolicyDocument(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect=Allow,
                    Action=[AssumeRole],
                    Principal=Principal("AWS", "arn:aws:iam::609973658768:user/cops"),
                )
            ],
        ),
        ManagedPolicyArns=policy_arn,
    )

def create_karpenter_role(cluster_name):
    """
    Create a managed policy for the IAM role.
    :param name: The name of the IAM role.
    :param policy_arn: The list of policy ARNs.
    :return: The Role object.
    """
    return Role(
         "KarpenterNodeRole",
        RoleName=Sub("KarpenterNodeRole-${cluster_name}"),
       
        AssumeRolePolicyDocument=PolicyDocument(
            Version="2012-10-17",
            Statement=[
                Statement(
                    Effect=Allow,
                    Action=[AssumeRole],
                    Principal=Principal("Service", [Sub("ec2.${AWS::URLSuffix}")])
                )
            ],
        ),
        ManagedPolicyArns=[
                Sub("arn:${AWS::Partition}:iam::aws:policy/AmazonEKS_CNI_Policy"),
                Sub("arn:${AWS::Partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"),
                Sub("arn:${AWS::Partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"),
                Sub("arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore")
            ],
    )


class CopsEventHandler(AWSCustomObject):
    """
    Custom resource for handling Cops events using a Lambda function.

    Attributes:
        resource_type (str): The type of the custom resource.
        props (dict): The properties required by the custom resource.
            - ServiceToken (str): The ARN of the Lambda function to invoke.
            - CopsRoleArn (str): The ARN of the CopsRole to assume.
            - AWSIntegrationID (str): The AWS Integration ID.
            - AccountID (str): The AWS Account ID.
    """
    resource_type = "Custom::CopsEventHandler"
    props = {
        "ServiceToken": (str, True),
        "CopsRoleArn": (str, True),
        "AWSIntegrationID": (str, True),
        "AccountID": (str, True)
    }


def main():
    for role in ["support", "updater", "provisioner"]:
        template = Template()

        aws_integration_id_param = template.add_parameter(Parameter(
            "AWSIntegrationID",
            Type="String",
            Description="Do not edit. This ID is used to provide secure access."
        ))

        description = READER_CF_DESCRIPTION
        ref = [Ref(template.add_resource(create_read_policy(role)))]

        if role == "updater":
            description = UPDATER_CF_DESCRIPTION

        if role == "provisioner":
            description = PROVISIONER_CF_DESCRIPTION
            ref.append(Ref(template.add_resource(create_provisioner_policy(role))))

        # This permission is required by Terraform for update/upgrade
        if role == "updater" or role == "provisioner":
            ref.append(Ref(template.add_resource(create_updater_policy(role))))

            
        template.add_resource(CopsEventHandler(
            "CopsEventHandler",
            ServiceToken=Sub("arn:aws:lambda:${AWS::Region}:609973658768:function:CopsEventHandler"),
            CopsRoleArn=Sub("arn:aws:lambda:${AWS::Region}:609973658768:function:CopsEventHandler"),
            AWSIntegrationID=Ref(aws_integration_id_param),
            AccountID=Sub("${AWS::AccountId}"),
            DependsOn="CrossAccountRoleForAWSTrustedAdvisorCops"
        ))
        
        template.set_description(description)
        file = f"cops-{role}"

        template.add_resource(create_role(file, ref))

        parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(parent_dir, "gen", f"cops-{role}-role.template.yaml")

        with open(path, "w") as file:
            file.write(template.to_yaml())
    template = Template()
    ref = []

    cluster_name = template.add_parameter(Parameter(
        "Cluster",
        Type="String",
        Description="Do not edit. This ID is used to provide secure access."
    ))

    ref.append(Ref(template.add_resource(create_karpenter_policy(cluster_name))))
    ref.append(Ref(template.add_resource(create_interruption_policy())))
    ref.append(Ref(template.add_resource(create_queue_policy())))
    ref.append(Ref(template.add_resource(create_schedule_rule())))
    ref.append(Ref(template.add_resource(create_rebalance_rule())))
    ref.append(Ref(template.add_resource(create_statechange_rule())))
    ref.append(Ref(template.add_resource(create_spot_rule())))

    description = KARPENTER_CF_DESCRIPTION


    template.set_description(description)
    file = "cops-karpenter-role.template.yaml"

    template.add_resource(create_karpenter_role(ref))

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(parent_dir, "gen", "cops-karpenter-role.template.yaml")

    with open(path, "w") as file:
        file.write(template.to_yaml())

if __name__ == "__main__":
    main()