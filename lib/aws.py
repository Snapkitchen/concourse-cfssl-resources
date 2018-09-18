# stdlib
from typing import Optional

# pip
import boto3

# local
import lib.hash


# =============================================================================
#
# constants
#
# =============================================================================

AWS_S3_CHECKSUM_METADATA_KEY_NAME = 'sha256'


# =============================================================================
# get_boto3_session
# =============================================================================
def get_boto3_session(
    access_key_id: str,
    secret_access_key: str,
    region_name: str
) -> boto3.session.Session:
    return boto3.session.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name=region_name)


# =============================================================================
# get_s3_resource
# =============================================================================
def get_s3_resource(
        boto3_session: boto3.session.Session,
        endpoint_url: Optional[str],
        disable_ssl: Optional[bool]) -> boto3.resources.base.ServiceResource:
    return boto3_session.resource(
        's3',
        endpoint_url=endpoint_url,
        use_ssl=False if disable_ssl else True)


# =============================================================================
# get_s3_object
# =============================================================================
def get_s3_object(
        s3_resource: boto3.resources.base.ServiceResource,
        bucket_name: str,
        key: str) -> boto3.resources.base.ServiceResource:
    return s3_resource.Object(bucket_name, key)


# =============================================================================
# format_s3_key_with_prefix
# =============================================================================
def format_s3_key_with_prefix(prefix: Optional[str], key: str) -> str:
    if prefix:
        return prefix + '/' + key
    else:
        return key


# =============================================================================
# get_s3_object_checksum
# =============================================================================
def get_s3_object_checksum(
        s3_object: boto3.resources.base.ServiceResource) -> str:
    return s3_object.metadata[AWS_S3_CHECKSUM_METADATA_KEY_NAME]


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
