"""Approved NEW-user scope: own bucket, no IAM/admin or other-bucket access.

Pure document builders, not evidence of MinIO runtime enforcement. Only a worker
with accepted exclusive authority may create/replace its own named policy.
"""

import re
from uuid import UUID


def resource_name(owner: UUID) -> str:
    if type(owner) is not UUID:
        raise ValueError("invalid_owner")
    return "ua-" + owner.hex


def _marker(owner: UUID, operation: UUID, generation: int) -> str:
    if type(owner) is not UUID or type(operation) is not UUID:
        raise ValueError("invalid_owner")
    if type(generation) is not int or not 1 <= generation < 2**63:
        raise ValueError("invalid_generation")
    return f"UA{owner.hex}Op{operation.hex}G{generation}"


def bucket_policy(
    *, owner: UUID, operation: UUID, generation: int, blocked: bool
) -> dict:
    if type(blocked) is not bool:
        raise ValueError("invalid_state")
    marker = _marker(owner, operation, generation)
    bucket = "arn:aws:s3:::" + resource_name(owner)
    if blocked:
        # Replace this exclusively owned policy's allow with explicit deny on
        # its complete bucket/object scope. This MinIO release requires S3 ARN
        # resources (not IAM's bare '*'); no other scope or data is changed.
        statements = [
            {
                "Sid": marker + "Deny",
                "Effect": "Deny",
                "Action": ["s3:*"],
                "Resource": [bucket, bucket + "/*"],
            }
        ]
    else:
        statements = [
            {
                "Sid": marker + "Bucket",
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                ],
                "Resource": [bucket],
            },
            {
                "Sid": marker + "Objects",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:AbortMultipartUpload",
                    "s3:ListMultipartUploadParts",
                ],
                "Resource": [bucket + "/*"],
            },
        ]
    return {"Version": "2012-10-17", "Statement": statements}


def policy_stamp(document: dict, owner: UUID) -> tuple[UUID, int, bool]:
    """Accept only the exact owned allow/deny templates, not a matching Sid alone.

    MinIO may serialize Action/Resource sets in another order. Array order is
    immaterial; unknown statements, conditions, principals or keys are refused.
    This verifies a document, not exclusivity, credentials or policy propagation.
    """
    if type(owner) is not UUID or type(document) is not dict:
        raise ValueError("policy_unverified")
    statements = document.get("Statement")
    if type(statements) is not list or len(statements) not in {1, 2}:
        raise ValueError("policy_unverified")
    first = statements[0]
    sid = first.get("Sid") if type(first) is dict else None
    match = re.fullmatch(
        rf"UA{owner.hex}Op([0-9a-f]{{32}})G([1-9][0-9]{{0,18}})(Deny|Bucket|Objects)",
        sid if type(sid) is str else "",
    )
    if not match:
        raise ValueError("policy_unverified")
    operation, generation = UUID(hex=match[1]), int(match[2])
    blocked = match[3] == "Deny"
    expected = bucket_policy(
        owner=owner, operation=operation, generation=generation, blocked=blocked
    )
    if _normalized(document) != _normalized(expected):
        raise ValueError("policy_unverified")
    return operation, generation, blocked


def _normalized(document: dict) -> tuple:
    if set(document) != {"Version", "Statement"}:
        raise ValueError("policy_unverified")
    statements = []
    for item in document["Statement"]:
        if type(item) is not dict or set(item) != {
            "Sid",
            "Effect",
            "Action",
            "Resource",
        }:
            raise ValueError("policy_unverified")
        arrays = []
        for key in ["Action", "Resource"]:
            values = item[key]
            # IAM libraries may encode singleton sets as strings.
            if type(values) is str:
                values = [values]
            if (
                type(values) is not list
                or not values
                or any(type(v) is not str for v in values)
            ):
                raise ValueError("policy_unverified")
            if len(set(values)) != len(values):
                raise ValueError("policy_unverified")
            arrays.append(tuple(sorted(values)))
        if type(item["Sid"]) is not str or type(item["Effect"]) is not str:
            raise ValueError("policy_unverified")
        statements.append((item["Sid"], item["Effect"], *arrays))
    if type(document["Version"]) is not str:
        raise ValueError("policy_unverified")
    return document["Version"], tuple(sorted(statements))
