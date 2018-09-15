# stdlib
import hashlib
import json
import sys
from typing import Optional, Any

# pip
import boto3

# =============================================================================
#
# constants
#
# =============================================================================

AWS_DEFAULT_REGION = 'us-east-1'
AWS_S3_CHECKSUM_METADATA_KEY_NAME = 'sha256'


# =============================================================================
#
# general
#
# =============================================================================

# =============================================================================
# log
# =============================================================================

def log(value: Any) -> None:
    print(value, file=sys.stderr)


# =============================================================================
# hello_world
# =============================================================================
def hello_world() -> None:
    log('hello world')


# =============================================================================
# read_concourse_input_payload
# =============================================================================
def read_concourse_input_payload() -> dict:
    return json.load(sys.stdin)


# =============================================================================
# write_concourse_output_payload
# =============================================================================
def write_concourse_output_payload(payload: Any) -> None:
    json.dump(payload, sys.stdout)


# =============================================================================
# s3_key_with_prefix
# =============================================================================
def s3_key_with_prefix(prefix: Optional[str], key: str) -> str:
    if prefix:
        return prefix + '/' + key
    else:
        return key


# =============================================================================
# _hash_string
# =============================================================================
def _hash_string(string: str) -> str:
    return hashlib.sha256(str.encode('utf-8')).hexdigest()


# =============================================================================
# hash_list
# =============================================================================
def hash_list(string_list: list) -> str:
    return _hash_string(''.join(string_list))


# =============================================================================
#
# boto3
#
# =============================================================================

# =============================================================================
# get_boto3_session
# =============================================================================
def get_boto3_session(config: dict) -> boto3.session.Session:
    return boto3.session.Session(
        aws_access_key_id=config.get('access_key_id'),
        aws_secret_access_key=config.get('secret_access_key'),
        region_name=config.get('region_name', AWS_DEFAULT_REGION))


# =============================================================================
# get_s3_resource
# =============================================================================
def get_s3_resource(
        session: boto3.session.Session,
        config: dict) -> boto3.resources.base.ServiceResource:
    return session.resource(
        's3',
        endpoint_url=config.get('endpoint'),
        use_ssl=not config.get('disable_ssl', False))


# =============================================================================
# get_s3_object
# =============================================================================
def get_s3_object(
        s3_resource: boto3.resources.base.ServiceResource,
        bucket_name: str,
        key: str) -> boto3.resources.base.ServiceResource:
    return s3_resource.Object(bucket_name, key)


# =============================================================================
# get_s3_object_checksum
# =============================================================================
def get_s3_object_checksum(
        s3_object: boto3.resources.base.ServiceResource):
    return s3_object.metadata[AWS_S3_CHECKSUM_METADATA_KEY_NAME]
