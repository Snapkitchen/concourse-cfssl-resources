# stdlib
import os.path
from typing import Optional

# pip
import boto3

# local
import lib.concourse
import lib.log


# =============================================================================
#
# constants
#
# =============================================================================

CERT_FILE_NAME = 'root-ca.pem'
PRIVATE_KEY_FILE_NAME = 'root-ca-key.pem'


# =============================================================================
#
# general
#
# =============================================================================

# =============================================================================
# get_certificate
# =============================================================================
def get_certificate(
        payload: dict,
        s3_resource: boto3.resources.base.ServiceResource
) -> boto3.resources.base.ServiceResource:
    return lib.concourse.get_s3_object_using_payload(
        payload,
        s3_resource,
        CERT_FILE_NAME)


# =============================================================================
# get_private_key
# =============================================================================
def get_private_key(
        payload: dict,
        s3_resource: boto3.resources.base.ServiceResource
) -> boto3.resources.base.ServiceResource:
    return lib.concourse.get_s3_object_using_payload(
        payload,
        s3_resource,
        PRIVATE_KEY_FILE_NAME)


# =============================================================================
# get_certificate_checksum
# =============================================================================
def get_certificate_checksum(
    root_ca_cert: boto3.resources.base.ServiceResource
) -> str:
    root_ca_cert_checksum = \
        lib.aws.get_s3_object_checksum(root_ca_cert)
    # log to output
    lib.log.log(f"root ca cert checksum: {root_ca_cert_checksum}")
    # return
    return root_ca_cert_checksum


# =============================================================================
# get_private_key_checksum
# =============================================================================
def get_private_key_checksum(
    root_ca_private_key: boto3.resources.base.ServiceResource
) -> str:
    root_ca_private_key_checksum = \
        lib.aws.get_s3_object_checksum(root_ca_private_key)
    # log to output
    lib.log.log(
        f"root ca private key checksum: {root_ca_private_key_checksum}")
    # return
    return root_ca_private_key_checksum


# =============================================================================
# get_checksum
# =============================================================================
def get_checksum(
        root_ca_cert_checksum: str,
        root_ca_private_key_checksum: str
) -> str:
    # ensure deterministic ordering of hash list for root ca
    root_ca_checksum = lib.hash.hash_list([root_ca_cert_checksum,
                                          root_ca_private_key_checksum])
    lib.log.log(f"root ca checksum: {root_ca_checksum}")
    return root_ca_checksum


# =============================================================================
# _download_root_ca_cert
# =============================================================================
def _download_root_ca_cert(
    root_ca_cert,
    root_ca_cert_checksum,
    destination_dir_path
) -> None:
    destination_file_path = os.path.join(destination_dir_path, CERT_FILE_NAME)
    lib.common.download_s3_object_to_path(
        root_ca_cert,
        root_ca_cert_checksum,
        destination_file_path)


# =============================================================================
# _download_root_ca_private_key
# =============================================================================
def _download_root_ca_private_key(
    root_ca_private_key,
    root_ca_private_key_checksum,
    destination_dir_path
) -> None:
    destination_file_path = \
        os.path.join(destination_dir_path, PRIVATE_KEY_FILE_NAME)
    lib.common.download_s3_object_to_path(
        root_ca_private_key,
        root_ca_private_key_checksum,
        destination_file_path)


# =============================================================================
# download
# =============================================================================
def download(
    source_config: dict,
    requested_checksum: str,
    destination_dir_path: str,
    save_certificate: Optional[bool],
    save_private_key: Optional[bool]
) -> None:
    # create the boto3 session using auth from source config
    boto3_session = lib.common.get_boto3_session(source_config)

    # create the s3 resource using the boto3 session and source config
    s3_resource = lib.common.get_s3_resource(boto3_session, source_config)

    # get the root ca cert object
    root_ca_cert = _root_ca_cert(source_config, s3_resource)

    # get the root ca private key object
    root_ca_private_key = _root_ca_private_key(source_config, s3_resource)

    # get the checksums
    root_ca_cert_checksum, root_ca_private_key_checksum = \
        _checksums(root_ca_cert, root_ca_private_key)

    # get the root ca checksum
    root_ca_checksum = \
        _checksum(root_ca_cert_checksum, root_ca_private_key_checksum)

    # compare the root ca checksum vs the requested checksum
    if requested_checksum != root_ca_checksum:
        # cannot continue if values do not match
        raise ValueError(f"current checksum '{root_ca_checksum}' does not"
                         f" match requested checksum '{requested_checksum}'")

    # download the certificate file, if requested
    if save_certificate:
        _download_root_ca_cert(
            root_ca_cert,
            root_ca_cert_checksum,
            destination_dir_path)

    # download the private key file, if requested
    if save_private_key:
        _download_root_ca_private_key(
            root_ca_private_key,
            root_ca_private_key_checksum,
            destination_dir_path)
