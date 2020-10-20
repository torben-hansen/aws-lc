#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

<<<<<<< HEAD
from util.metadata import AWS_REGION, AWS_ACCOUNT, LINUX_AARCH_ECR_REPO, LINUX_X86_ECR_REPO, WINDOWS_ECR_REPO
=======
from util.metadata import AWS_REGION, AWS_ACCOUNT, LINUX_AARCH_ECR_REPO, LINUX_X86_ECR_REPO, WINDOWS_X86_ECR_REPO
>>>>>>> main2


def codebuild_batch_policy_in_json(project_ids):
    """
    Define an IAM policy statement for CodeBuild batch operation.
    :param project_ids: a list of CodeBuild project id.
    :return: an IAM policy statement in json.
    """
    resources = []
    for project_id in project_ids:
        resources.append("arn:aws:codebuild:{}:{}:project/{}*".format(AWS_REGION, AWS_ACCOUNT, project_id))
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "codebuild:StartBuild",
                    "codebuild:StopBuild",
                    "codebuild:RetryBuild"
                ],
                "Resource": resources
            }
        ]
    }


def s3_read_write_policy_in_json(s3_bucket_name):
    """
    Define an IAM policy statement for reading and writing to S3 bucket.
    :return: an IAM policy statement in json.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:Put*",
                    "s3:Get*"
                ],
                "Resource": [
                    "arn:aws:s3:::{}/*".format(s3_bucket_name)
                ]
            }
        ]
    }


def ecr_power_user_policy_in_json():
    """
    Define an AWS-LC specific IAM policy statement for AWS ECR power user used to create new docker images.
    :return: an IAM policy statement in json.
    """
    ecr_arn_prefix = "arn:aws:ecr:{}:{}:repository".format(AWS_REGION, AWS_ACCOUNT)
    linux_x86_ecr_arn = "{}/{}".format(ecr_arn_prefix, LINUX_X86_ECR_REPO)
    linux_aarch_ecr_arn = "{}/{}".format(ecr_arn_prefix, LINUX_AARCH_ECR_REPO)
<<<<<<< HEAD
    windows_ecr_arn = "{}/{}".format(ecr_arn_prefix, WINDOWS_ECR_REPO)
=======
    windows_ecr_arn = "{}/{}".format(ecr_arn_prefix, WINDOWS_X86_ECR_REPO)
>>>>>>> main2
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:GetAuthorizationToken"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:GetRepositoryPolicy",
                    "ecr:DescribeRepositories",
                    "ecr:ListImages",
                    "ecr:DescribeImages",
                    "ecr:BatchGetImage",
                    "ecr:GetLifecyclePolicy",
                    "ecr:GetLifecyclePolicyPreview",
                    "ecr:ListTagsForResource",
                    "ecr:DescribeImageScanFindings",
                    "ecr:InitiateLayerUpload",
                    "ecr:UploadLayerPart",
                    "ecr:CompleteLayerUpload",
                    "ecr:PutImage"
                ],
                "Resource": [
                    linux_x86_ecr_arn,
                    linux_aarch_ecr_arn,
                    windows_ecr_arn
                ]
            }
        ]
    }
