# stdlib
import json
import sys
from typing import Any

# pip
import boto3

# local
import lib.aws


# =============================================================================
# read_payload
# =============================================================================
def read_payload() -> dict:
    return json.load(sys.stdin)


# =============================================================================
# write_payload
# =============================================================================
def write_payload(payload: Any) -> None:
    json.dump(payload, sys.stdout)


# =============================================================================
# get_boto3_session_using_payload
# =============================================================================
def get_boto3_session_using_payload(payload: dict) -> boto3.session.Session:
    # get a boto3 session
    return lib.aws.get_boto3_session(
        payload['source']['access_key_id'],
        payload['source']['secret_access_key'],
        payload['source']['region_name'])


# =============================================================================
# get_s3_resource_using_payload
# =============================================================================
def get_s3_resource_using_payload(
    payload: dict,
    boto3_session: boto3.session.Session
) -> boto3.resources.base.ServiceResource:
    return lib.aws.get_s3_resource(
        boto3_session,
        payload['source'].get('endpoint'),
        payload['source'].get('disable_ssl'))


# =============================================================================
# get_s3_object_using_payload
# =============================================================================
def get_s3_object_using_payload(
        payload: dict,
        s3_resource: boto3.resources.base.ServiceResource,
        file_name: str
) -> boto3.resources.base.ServiceResource:
    return lib.aws.get_s3_object(
        s3_resource,
        payload['source']['bucket'],
        lib.aws.format_s3_key_with_prefix(
            payload['source'].get('prefix'),
            file_name))
