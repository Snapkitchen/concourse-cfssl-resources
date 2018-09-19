# stdlib
from typing import Optional

# pip
import boto3

# local
import lib.concourse
import lib.hash


# =============================================================================
#
# constants
#
# =============================================================================

CHECKSUM_METADATA_KEY_NAME: str = 'sha256'


# =============================================================================
#
# functions
#
# =============================================================================

# =============================================================================
# _format_s3_key_with_prefix
# =============================================================================
def _format_s3_key_with_prefix(prefix: Optional[str], key: str) -> str:
    if prefix:
        return prefix + '/' + key
    else:
        return key


# =============================================================================
# get_s3_object
# =============================================================================
def get_s3_object(file_name: str) -> boto3.resources.base.ServiceResource:
    return s3_resource.Object(
        lib.concourse.payload['source']['bucket_name'],
        _format_s3_key_with_prefix(
            lib.concourse.payload['source'].get('prefix'),
            file_name))


# =============================================================================
# get_s3_object_checksum
# =============================================================================
def get_s3_object_checksum(
    s3_object: boto3.resources.base.ServiceResource
) -> boto3.resources.base.ServiceResource:
    return s3_object.metadata[CHECKSUM_METADATA_KEY_NAME]


# =============================================================================
# download_s3_object_to_path
# =============================================================================
def download_s3_object_to_path(
    s3_object,
    expected_checksum,
    destination_file_path
) -> None:
    s3_object.download_file(destination_file_path)
    destination_file_hash = lib.hash.hash_file(destination_file_path)
    if expected_checksum != destination_file_hash:
        raise ValueError(f"expected checksum '{expected_checksum}' does"
                         f" not match file checksum '{destination_file_hash}'")


# =============================================================================
#
# properties
#
# =============================================================================

# =============================================================================
# boto3_session
# =============================================================================
boto3_session = boto3.session.Session(
    aws_access_key_id=lib.concourse.payload['source']['access_key_id'],
    aws_secret_access_key=lib.concourse.payload['source']['secret_access_key'],
    region_name=lib.concourse.payload['source']['region_name'])


# =============================================================================
# s3_resource
# =============================================================================
s3_resource = boto3_session.resource(
    's3',
    endpoint_url=lib.concourse.payload['source'].get('endpoint'),
    use_ssl=(False if
             lib.concourse.payload['source'].get('disable_ssl')
             else True))
