# stdlib
import hashlib
import json
import os
import sys
from typing import Any, Optional

# pip
import boto3

# local
import lib.cfssl
from lib.log import log


# =============================================================================
#
# constants
#
# =============================================================================

CHECKSUM_METADATA_KEY_NAME: str = 'sha256'

ROOT_CA_FILE_PREFIX: str = 'root-ca'
ROOT_CA_CERTIFICATE_FILE_NAME: str = f"{ROOT_CA_FILE_PREFIX}.pem"
ROOT_CA_PRIVATE_KEY_FILE_NAME: str = f"{ROOT_CA_FILE_PREFIX}-key.pem"

INTERMEDIATE_CA_FILE_PREFIX: str = 'intermediate-ca'
INTERMEDIATE_CA_CERTIFICATE_FILE_NAME: str = \
    f"{INTERMEDIATE_CA_FILE_PREFIX}.pem"
INTERMEDIATE_CA_PRIVATE_KEY_FILE_NAME: str = \
    f"{INTERMEDIATE_CA_FILE_PREFIX}-key.pem"


# =============================================================================
#
# private hash functions
#
# =============================================================================

# =============================================================================
# _hash_string
# =============================================================================
def _hash_string(string: str) -> str:
    return hashlib.sha256(string.encode('utf-8')).hexdigest()


# =============================================================================
# _hash_list
# =============================================================================
def _hash_list(string_list: list) -> str:
    return _hash_string(''.join(string_list))


# =============================================================================
# _hash_file
# =============================================================================
def _hash_file(file_path: str) -> str:
    BUFFER_SIZE = 65536
    file_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while True:
            file_data = file.read(BUFFER_SIZE)
            if not file_data:
                break
            file_hash.update(file_data)
    return file_hash.hexdigest()


# =============================================================================
#
# private s3 functions
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
# _get_boto3_session
# =============================================================================
def _get_boto3_session(payload: dict) -> boto3.session.Session:
    return boto3.session.Session(
        aws_access_key_id=payload['source']['access_key_id'],
        aws_secret_access_key=payload['source']['secret_access_key'],
        region_name=payload['source']['region_name'])


# =============================================================================
# _s3_resource
# =============================================================================
def _get_s3_resource(
    payload: dict,
    boto3_session: boto3.session.Session
) -> boto3.resources.base.ServiceResource:
    return boto3_session.resource(
        's3',
        endpoint_url=payload['source'].get('endpoint'),
        use_ssl=(False if
                 payload['source'].get('disable_ssl')
                 else True))


# =============================================================================
# _get_s3_object
# =============================================================================
def _get_s3_object(
    payload: dict,
    s3_resource: boto3.resources.base.ServiceResource,
    file_name: str
) -> boto3.resources.base.ServiceResource:
    return s3_resource.Object(
        payload['source']['bucket_name'],
        _format_s3_key_with_prefix(
            payload['source'].get('prefix'),
            file_name))


# =============================================================================
# _get_s3_object_checksum
# =============================================================================
def _get_s3_object_checksum(
    s3_object: boto3.resources.base.ServiceResource
) -> boto3.resources.base.ServiceResource:
    # workaround for https://github.com/boto/boto3/issues/1709
    # which results in case-sensitive keys.
    # since it's impossible to end up with two different keys
    # in the metadata dict with the same case-insensitive name
    # (e.g. 'Foo' and 'foo'), then we can assume the lowercased
    # version of the key is the same as the lowercased
    # version of the expected key
    # in addition, when setting the value, the case of the
    # metadata key does not matter, by design

    # loop through each key in the metadata dict
    for key in s3_object.metadata.keys():
        # if the lowercased version of the key
        # matches the lowercased version of the expected key
        if key.lower() == CHECKSUM_METADATA_KEY_NAME.lower():
            # return the actual key's value
            return s3_object.metadata[key]
    # otherwise, if we didn't return, throw a key error
    raise KeyError(f"metadata key '{CHECKSUM_METADATA_KEY_NAME}' not found")


# =============================================================================
# _download_s3_object_to_path
# =============================================================================
def _download_s3_object_to_path(
    s3_object,
    expected_checksum,
    destination_file_path
) -> None:
    s3_object.download_file(destination_file_path)
    destination_file_hash = _hash_file(destination_file_path)
    if expected_checksum != destination_file_hash:
        raise ValueError(f"expected checksum '{expected_checksum}' does"
                         f" not match file checksum '{destination_file_hash}'")


# =============================================================================
# _upload_s3_object_to_path
# =============================================================================
def _upload_s3_object_to_path(
    s3_object,
    checksum,
    source_file_path
) -> None:
    s3_object.upload_file(source_file_path,
                          ExtraArgs={
                              'Metadata': {
                                  CHECKSUM_METADATA_KEY_NAME: checksum
                              }})


# =============================================================================
#
# private io functions
#
# =============================================================================

# =============================================================================
# _get_repository_dir_path
# =============================================================================
def _get_repository_dir_path() -> str:
    return sys.argv[1]


# =============================================================================
# _read_payload
# =============================================================================
def _read_payload(stream=sys.stdin) -> Any:
    return json.load(stream)


# =============================================================================
# _write_payload
# =============================================================================
def _write_payload(payload: Any, stream=sys.stdout) -> None:
    json.dump(payload, stream)


# =============================================================================
# _file_is_downloaded
# =============================================================================
def _file_is_downloaded(file_path: str) -> bool:
    return os.path.isfile(file_path)


# =============================================================================
# _get_repository_file_path
# =============================================================================
def _get_repository_file_path(
        repository_dir_path: str, file_name: str) -> str:
    return os.path.join(repository_dir_path, file_name)


# =============================================================================
#
# private decision functions
#
# =============================================================================

# =============================================================================
# _should_download_certificate
# =============================================================================
def _should_download_certificate(payload: dict) -> bool:
    if 'params' in payload:
        return payload['params'].get('save_certificate',
                                     True) is True
    else:
        return True


# =============================================================================
# _should_download_private_key
# =============================================================================
def _should_download_private_key(payload: dict) -> bool:
    if 'params' in payload:
        return payload['params'].get('save_private_key',
                                     False) is True
    else:
        return False


# =============================================================================
#
# private checksum functions
#
# =============================================================================

# =============================================================================
# _get_keypair_checksum
# =============================================================================
def _get_keypair_checksum(
    certificate_checksum: str,
    private_key_checksum: str
) -> str:
    return _hash_list([certificate_checksum, private_key_checksum])


# =============================================================================
# _checksum_exists
# =============================================================================
def _checksum_exists(
    payload: dict,
    checksum: str
) -> bool:
    return payload['version']['checksum'] == checksum


# =============================================================================
#
# private utility functions
#
# =============================================================================


# =============================================================================
# _create_check_payload
# =============================================================================
def _create_check_payload(checksum: str) -> list:
    return [{'checksum': checksum}]


# =============================================================================
# _create_in_payload
# =============================================================================
def _create_in_payload(
        payload: dict,
        certificate_file_name: str,
        certificate_file_path: str,
        certificate_checksum: str,
        private_key_file_name: str,
        private_key_file_path: str,
        private_key_checksum: str) -> dict:
    in_payload: dict = {
        'version': {
            'checksum': payload['version']['checksum']
        },
        'metadata': []
    }
    if _file_is_downloaded(certificate_file_path):
        in_payload['metadata'].extend(
            _create_certificate_metadata(
                certificate_file_name,
                certificate_checksum))
    if _file_is_downloaded(private_key_file_path):
        in_payload['metadata'].extend(
            _create_private_key_metadata(
                private_key_file_name,
                private_key_checksum))
    return in_payload


# =============================================================================
# _create_out_payload
# =============================================================================
def _create_out_payload(
    payload: dict,
    checksum: str,
    certificate_file_name: str,
    certificate_checksum: str,
    private_key_file_name: str,
    private_key_checksum: str
) -> dict:
    out_payload: dict = {
        'version': {
            'checksum': checksum
        },
        'metadata': []
    }
    out_payload['metadata'].extend(
        _create_certificate_metadata(
            certificate_file_name,
            certificate_checksum))
    out_payload['metadata'].extend(
        _create_private_key_metadata(
            private_key_file_name,
            private_key_checksum))
    return out_payload


# =============================================================================
# _create_certificate_metadata
# =============================================================================
def _create_certificate_metadata(
        certificate_file_name: str,
        certificate_checksum: str) -> list:
    return [
        {
            'name': 'certificate_file_name',
            'value': certificate_file_name
        },
        {
            'name': 'certificate_checksum',
            'value': certificate_checksum
        }]


# =============================================================================
# _create_private_key_metadata
# =============================================================================
def _create_private_key_metadata(
        private_key_file_name: str,
        private_key_checksum: str) -> list:
    return [
        {
            'name': 'private_key_file_name',
            'value': private_key_file_name
        },
        {
            'name': 'private_key_checksum',
            'value': private_key_checksum
        }]


# =============================================================================
#
# private lifecycle functions
#
# =============================================================================

# =============================================================================
# _do_check
# =============================================================================
def _do_check(checksum: str) -> None:
    _write_payload(_create_check_payload(checksum))


# =============================================================================
#
# root ca lifecycle functions
#
# =============================================================================

# =============================================================================
# root_ca_check
# =============================================================================
def root_ca_check() -> None:
    # read input
    input_payload = _read_payload()

    # create s3 objects
    boto3_session = _get_boto3_session(input_payload)
    s3_resource = _get_s3_resource(input_payload, boto3_session)
    root_ca_certificate = \
        _get_s3_object(
            input_payload,
            s3_resource,
            ROOT_CA_CERTIFICATE_FILE_NAME)
    root_ca_private_key = \
        _get_s3_object(
            input_payload,
            s3_resource,
            ROOT_CA_PRIVATE_KEY_FILE_NAME)

    # get remote checksums
    root_ca_certificate_checksum = \
        _get_s3_object_checksum(root_ca_certificate)
    root_ca_private_key_checksum = \
        _get_s3_object_checksum(root_ca_private_key)

    log(f"root ca certificate checksum: {root_ca_certificate_checksum}")
    log(f"root ca private key checksum: {root_ca_private_key_checksum}")

    # get remote checksum
    root_ca_checksum = \
        _get_keypair_checksum(
            root_ca_certificate_checksum,
            root_ca_private_key_checksum)

    log(f"root ca checksum: {root_ca_checksum}")

    # do check
    _do_check(root_ca_checksum)


# =============================================================================
# root_ca_in
# =============================================================================
def root_ca_in() -> None:
    # read input
    input_payload = _read_payload()
    repository_dir = _get_repository_dir_path()

    # create s3 objects
    boto3_session = _get_boto3_session(input_payload)
    s3_resource = _get_s3_resource(input_payload, boto3_session)
    root_ca_certificate = \
        _get_s3_object(
            input_payload,
            s3_resource,
            ROOT_CA_CERTIFICATE_FILE_NAME)
    root_ca_private_key = \
        _get_s3_object(
            input_payload,
            s3_resource,
            ROOT_CA_PRIVATE_KEY_FILE_NAME)

    # get remote checksums
    root_ca_certificate_checksum = \
        _get_s3_object_checksum(root_ca_certificate)
    root_ca_private_key_checksum = \
        _get_s3_object_checksum(root_ca_private_key)

    log(f"root ca certificate checksum: {root_ca_certificate_checksum}")
    log(f"root ca private key checksum: {root_ca_private_key_checksum}")

    # get remote checksum
    root_ca_checksum = \
        _get_keypair_checksum(
            root_ca_certificate_checksum,
            root_ca_private_key_checksum)

    log(f"root ca checksum: {root_ca_checksum}")

    # get file paths
    root_ca_certificate_file_path = \
        _get_repository_file_path(
            repository_dir,
            ROOT_CA_CERTIFICATE_FILE_NAME)
    root_ca_private_key_file_path = \
        _get_repository_file_path(
            repository_dir,
            ROOT_CA_PRIVATE_KEY_FILE_NAME)

    # check for requested checksum
    # and download
    if _checksum_exists(
            input_payload,
            root_ca_checksum):
        if _should_download_certificate(input_payload):
            _download_s3_object_to_path(
                root_ca_certificate,
                root_ca_certificate_checksum,
                root_ca_certificate_file_path)
        if _should_download_private_key(input_payload):
            _download_s3_object_to_path(
                root_ca_private_key,
                root_ca_private_key_checksum,
                root_ca_private_key_file_path)
    else:
        # cannot continue if checksum is unavailable
        raise ValueError(f"requested checksum is unavailable")

    # create output payload
    output_payload = _create_in_payload(
        input_payload,
        ROOT_CA_CERTIFICATE_FILE_NAME,
        root_ca_certificate_file_path,
        root_ca_certificate_checksum,
        ROOT_CA_PRIVATE_KEY_FILE_NAME,
        root_ca_private_key_file_path,
        root_ca_private_key_checksum)

    # write output
    _write_payload(output_payload)


# =============================================================================
# root_ca_out
# =============================================================================
def root_ca_out() -> None:
    # read input
    input_payload = _read_payload()
    repository_dir = _get_repository_dir_path()

    # create s3 objects
    boto3_session = _get_boto3_session(input_payload)
    s3_resource = _get_s3_resource(input_payload, boto3_session)
    root_ca_certificate = \
        _get_s3_object(
            input_payload,
            s3_resource,
            ROOT_CA_CERTIFICATE_FILE_NAME)
    root_ca_private_key = \
        _get_s3_object(
            input_payload,
            s3_resource,
            ROOT_CA_PRIVATE_KEY_FILE_NAME)

    # create root ca key pair
    lib.cfssl.create_root_ca(
        input_payload,
        repository_dir,
        ROOT_CA_FILE_PREFIX)

    # get file paths
    root_ca_certificate_file_path = \
        _get_repository_file_path(
            repository_dir,
            ROOT_CA_CERTIFICATE_FILE_NAME)
    root_ca_private_key_file_path = \
        _get_repository_file_path(
            repository_dir,
            ROOT_CA_PRIVATE_KEY_FILE_NAME)

    # get local checksums
    root_ca_certificate_checksum = \
        _hash_file(root_ca_certificate_file_path)
    root_ca_private_key_checksum = \
        _hash_file(root_ca_private_key_file_path)

    log(f"root ca certificate checksum: {root_ca_certificate_checksum}")
    log(f"root ca private key checksum: {root_ca_private_key_checksum}")

    # get local checksum
    root_ca_checksum = \
        _get_keypair_checksum(
            root_ca_certificate_checksum,
            root_ca_private_key_checksum)

    log(f"root ca checksum: {root_ca_checksum}")

    # upload certificate
    _upload_s3_object_to_path(
        root_ca_certificate,
        root_ca_certificate_checksum,
        root_ca_certificate_file_path)

    # upload private key
    _upload_s3_object_to_path(
        root_ca_private_key,
        root_ca_private_key_checksum,
        root_ca_private_key_file_path)

    # create output payload
    output_payload = _create_out_payload(
        input_payload,
        root_ca_checksum,
        ROOT_CA_CERTIFICATE_FILE_NAME,
        root_ca_certificate_checksum,
        ROOT_CA_PRIVATE_KEY_FILE_NAME,
        root_ca_private_key_checksum)

    # write output
    _write_payload(output_payload)


# =============================================================================
#
# intermediate ca lifecycle functions
#
# =============================================================================

# =============================================================================
# intermediate_ca_check
# =============================================================================
def intermediate_ca_check() -> None:
    # read input
    input_payload = _read_payload()

    # create s3 objects
    boto3_session = _get_boto3_session(input_payload)
    s3_resource = _get_s3_resource(input_payload, boto3_session)
    intermediate_ca_certificate = \
        _get_s3_object(
            input_payload,
            s3_resource,
            INTERMEDIATE_CA_CERTIFICATE_FILE_NAME)
    intermediate_ca_private_key = \
        _get_s3_object(
            input_payload,
            s3_resource,
            INTERMEDIATE_CA_PRIVATE_KEY_FILE_NAME)

    # get remote checksums
    intermediate_ca_certificate_checksum = \
        _get_s3_object_checksum(intermediate_ca_certificate)
    intermediate_ca_private_key_checksum = \
        _get_s3_object_checksum(intermediate_ca_private_key)

    log('intermediate ca certificate checksum: '
        f"{intermediate_ca_certificate_checksum}")
    log('intermediate ca private key checksum: '
        f"{intermediate_ca_private_key_checksum}")

    # get remote checksum
    intermediate_ca_checksum = \
        _get_keypair_checksum(
            intermediate_ca_certificate_checksum,
            intermediate_ca_private_key_checksum)

    log(f"intermediate ca checksum: {intermediate_ca_checksum}")

    # do check
    _do_check(intermediate_ca_checksum)


# =============================================================================
# intermediate_ca_in
# =============================================================================
def intermediate_ca_in() -> None:
    # read input
    input_payload = _read_payload()
    repository_dir = _get_repository_dir_path()

    # create s3 objects
    boto3_session = _get_boto3_session(input_payload)
    s3_resource = _get_s3_resource(input_payload, boto3_session)
    intermediate_ca_certificate = \
        _get_s3_object(
            input_payload,
            s3_resource,
            INTERMEDIATE_CA_CERTIFICATE_FILE_NAME)
    intermediate_ca_private_key = \
        _get_s3_object(
            input_payload,
            s3_resource,
            INTERMEDIATE_CA_PRIVATE_KEY_FILE_NAME)

    # get remote checksums
    intermediate_ca_certificate_checksum = \
        _get_s3_object_checksum(intermediate_ca_certificate)
    intermediate_ca_private_key_checksum = \
        _get_s3_object_checksum(intermediate_ca_private_key)

    log('intermediate ca certificate checksum: '
        f"{intermediate_ca_certificate_checksum}")
    log('intermediate ca private key checksum: '
        f"{intermediate_ca_private_key_checksum}")

    # get remote checksum
    intermediate_ca_checksum = \
        _get_keypair_checksum(
            intermediate_ca_certificate_checksum,
            intermediate_ca_private_key_checksum)

    log(f"intermediate ca checksum: {intermediate_ca_checksum}")

    # get file paths
    intermediate_ca_certificate_file_path = \
        _get_repository_file_path(
            repository_dir,
            INTERMEDIATE_CA_CERTIFICATE_FILE_NAME)
    intermediate_ca_private_key_file_path = \
        _get_repository_file_path(
            repository_dir,
            INTERMEDIATE_CA_PRIVATE_KEY_FILE_NAME)

    # check for requested checksum
    # and download
    if _checksum_exists(
            input_payload,
            intermediate_ca_checksum):
        if _should_download_certificate(input_payload):
            _download_s3_object_to_path(
                intermediate_ca_certificate,
                intermediate_ca_certificate_checksum,
                intermediate_ca_certificate_file_path)
        if _should_download_private_key(input_payload):
            _download_s3_object_to_path(
                intermediate_ca_private_key,
                intermediate_ca_private_key_checksum,
                intermediate_ca_private_key_file_path)
    else:
        # cannot continue if checksum is unavailable
        raise ValueError(f"requested checksum is unavailable")

    # create output payload
    output_payload = _create_in_payload(
        input_payload,
        INTERMEDIATE_CA_CERTIFICATE_FILE_NAME,
        intermediate_ca_certificate_file_path,
        intermediate_ca_certificate_checksum,
        INTERMEDIATE_CA_PRIVATE_KEY_FILE_NAME,
        intermediate_ca_private_key_file_path,
        intermediate_ca_private_key_checksum)

    # write output
    _write_payload(output_payload)


# =============================================================================
# intermediate_ca_out
# =============================================================================
def intermediate_ca_out() -> None:
    # read input
    input_payload = _read_payload()
    repository_dir = _get_repository_dir_path()

    # create root ca s3 objects
    boto3_session = _get_boto3_session(input_payload)
    s3_resource = _get_s3_resource(input_payload, boto3_session)
    root_ca_certificate = \
        _get_s3_object(
            input_payload,
            s3_resource,
            ROOT_CA_CERTIFICATE_FILE_NAME)
    root_ca_private_key = \
        _get_s3_object(
            input_payload,
            s3_resource,
            ROOT_CA_PRIVATE_KEY_FILE_NAME)

    # get root ca remote checksums
    root_ca_certificate_checksum = \
        _get_s3_object_checksum(root_ca_certificate)
    root_ca_private_key_checksum = \
        _get_s3_object_checksum(root_ca_private_key)

    log(f"root ca certificate checksum: {root_ca_certificate_checksum}")
    log(f"root ca private key checksum: {root_ca_private_key_checksum}")

    # get root ca remote checksum
    root_ca_checksum = \
        _get_keypair_checksum(
            root_ca_certificate_checksum,
            root_ca_private_key_checksum)

    log(f"root ca checksum: {root_ca_checksum}")

    # get root ca file paths
    root_ca_certificate_file_path = \
        _get_repository_file_path(
            repository_dir,
            ROOT_CA_CERTIFICATE_FILE_NAME)
    root_ca_private_key_file_path = \
        _get_repository_file_path(
            repository_dir,
            ROOT_CA_PRIVATE_KEY_FILE_NAME)

    # download root ca keypair
    _download_s3_object_to_path(
        root_ca_certificate,
        root_ca_certificate_checksum,
        root_ca_certificate_file_path)
    _download_s3_object_to_path(
        root_ca_private_key,
        root_ca_private_key_checksum,
        root_ca_private_key_file_path)

    # create intermediate ca key pair
    lib.cfssl.create_intermediate_ca(
        input_payload,
        repository_dir,
        INTERMEDIATE_CA_FILE_PREFIX,
        ROOT_CA_CERTIFICATE_FILE_NAME,
        ROOT_CA_PRIVATE_KEY_FILE_NAME)

    # get intermediate ca file paths
    intermediate_ca_certificate_file_path = \
        _get_repository_file_path(
            repository_dir,
            INTERMEDIATE_CA_CERTIFICATE_FILE_NAME)
    intermediate_ca_private_key_file_path = \
        _get_repository_file_path(
            repository_dir,
            INTERMEDIATE_CA_PRIVATE_KEY_FILE_NAME)

    # get intermediate ca local checksums
    intermediate_ca_certificate_checksum = \
        _hash_file(intermediate_ca_certificate_file_path)
    intermediate_ca_private_key_checksum = \
        _hash_file(intermediate_ca_private_key_file_path)

    log('intermediate ca certificate checksum: '
        f"{intermediate_ca_certificate_checksum}")
    log('intermediate ca private key checksum: '
        f"{intermediate_ca_private_key_checksum}")

    # get intermediate ca local checksum
    intermediate_ca_checksum = \
        _get_keypair_checksum(
            intermediate_ca_certificate_checksum,
            intermediate_ca_private_key_checksum)

    log(f"intermediate ca checksum: {intermediate_ca_checksum}")

    # create intermediate ca s3 objects
    intermediate_ca_certificate = \
        _get_s3_object(
            input_payload,
            s3_resource,
            INTERMEDIATE_CA_CERTIFICATE_FILE_NAME)
    intermediate_ca_private_key = \
        _get_s3_object(
            input_payload,
            s3_resource,
            INTERMEDIATE_CA_PRIVATE_KEY_FILE_NAME)

    # upload certificate
    _upload_s3_object_to_path(
        intermediate_ca_certificate,
        intermediate_ca_certificate_checksum,
        intermediate_ca_certificate_file_path)

    # upload private key
    _upload_s3_object_to_path(
        intermediate_ca_private_key,
        intermediate_ca_private_key_checksum,
        intermediate_ca_private_key_file_path)

    # create output payload
    output_payload = _create_out_payload(
        input_payload,
        intermediate_ca_checksum,
        INTERMEDIATE_CA_CERTIFICATE_FILE_NAME,
        intermediate_ca_certificate_checksum,
        INTERMEDIATE_CA_PRIVATE_KEY_FILE_NAME,
        intermediate_ca_private_key_checksum)

    # write output
    _write_payload(output_payload)


# =============================================================================
#
# leaf lifecycle functions
#
# =============================================================================

# =============================================================================
# leaf_check
# =============================================================================
def leaf_check() -> None:
    # read input
    input_payload = _read_payload()

    # get file names
    leaf_file_prefix = input_payload['source']['leaf_name']
    leaf_certificate_file_name = f"{leaf_file_prefix}.pem"
    leaf_private_key_file_name = f"{leaf_file_prefix}-key.pem"

    # create s3 objects
    boto3_session = _get_boto3_session(input_payload)
    s3_resource = _get_s3_resource(input_payload, boto3_session)
    leaf_certificate = \
        _get_s3_object(
            input_payload,
            s3_resource,
            leaf_certificate_file_name)
    leaf_private_key = \
        _get_s3_object(
            input_payload,
            s3_resource,
            leaf_private_key_file_name)

    # get remote checksums
    leaf_certificate_checksum = \
        _get_s3_object_checksum(leaf_certificate)
    leaf_private_key_checksum = \
        _get_s3_object_checksum(leaf_private_key)

    log('leaf certificate checksum: '
        f"{leaf_certificate_checksum}")
    log('leaf private key checksum: '
        f"{leaf_private_key_checksum}")

    # get remote checksum
    leaf_checksum = \
        _get_keypair_checksum(
            leaf_certificate_checksum,
            leaf_private_key_checksum)

    log(f"leaf checksum: {leaf_checksum}")

    # do check
    _do_check(leaf_checksum)


# =============================================================================
# leaf_in
# =============================================================================
def leaf_in() -> None:
    # read input
    input_payload = _read_payload()
    repository_dir = _get_repository_dir_path()

    # get file names
    leaf_file_prefix = input_payload['source']['leaf_name']
    leaf_certificate_file_name = f"{leaf_file_prefix}.pem"
    leaf_private_key_file_name = f"{leaf_file_prefix}-key.pem"

    # create s3 objects
    boto3_session = _get_boto3_session(input_payload)
    s3_resource = _get_s3_resource(input_payload, boto3_session)
    leaf_certificate = \
        _get_s3_object(
            input_payload,
            s3_resource,
            leaf_certificate_file_name)
    leaf_private_key = \
        _get_s3_object(
            input_payload,
            s3_resource,
            leaf_private_key_file_name)

    # get remote checksums
    leaf_certificate_checksum = \
        _get_s3_object_checksum(leaf_certificate)
    leaf_private_key_checksum = \
        _get_s3_object_checksum(leaf_private_key)

    log('leaf certificate checksum: '
        f"{leaf_certificate_checksum}")
    log('leaf private key checksum: '
        f"{leaf_private_key_checksum}")

    # get remote checksum
    leaf_checksum = \
        _get_keypair_checksum(
            leaf_certificate_checksum,
            leaf_private_key_checksum)

    log(f"leaf checksum: {leaf_checksum}")

    # get file paths
    leaf_certificate_file_path = \
        _get_repository_file_path(
            repository_dir,
            leaf_certificate_file_name)
    leaf_private_key_file_path = \
        _get_repository_file_path(
            repository_dir,
            leaf_private_key_file_name)

    # check for requested checksum
    # and download
    if _checksum_exists(
            input_payload,
            leaf_checksum):
        if _should_download_certificate(input_payload):
            _download_s3_object_to_path(
                leaf_certificate,
                leaf_certificate_checksum,
                leaf_certificate_file_path)
        if _should_download_private_key(input_payload):
            _download_s3_object_to_path(
                leaf_private_key,
                leaf_private_key_checksum,
                leaf_private_key_file_path)
    else:
        # cannot continue if checksum is unavailable
        raise ValueError(f"requested checksum is unavailable")

    # create output payload
    output_payload = _create_in_payload(
        input_payload,
        leaf_certificate_file_name,
        leaf_certificate_file_path,
        leaf_certificate_checksum,
        leaf_private_key_file_name,
        leaf_private_key_file_path,
        leaf_private_key_checksum)

    # write output
    _write_payload(output_payload)


# =============================================================================
# leaf_out
# =============================================================================
def leaf_out() -> None:
    # read input
    input_payload = _read_payload()
    repository_dir = _get_repository_dir_path()

    # create intermediate ca s3 objects
    boto3_session = _get_boto3_session(input_payload)
    s3_resource = _get_s3_resource(input_payload, boto3_session)
    intermediate_ca_certificate = \
        _get_s3_object(
            input_payload,
            s3_resource,
            INTERMEDIATE_CA_CERTIFICATE_FILE_NAME)
    intermediate_ca_private_key = \
        _get_s3_object(
            input_payload,
            s3_resource,
            INTERMEDIATE_CA_PRIVATE_KEY_FILE_NAME)

    # get intermediate ca remote checksums
    intermediate_ca_certificate_checksum = \
        _get_s3_object_checksum(intermediate_ca_certificate)
    intermediate_ca_private_key_checksum = \
        _get_s3_object_checksum(intermediate_ca_private_key)

    log('intermediate ca certificate checksum: '
        f"{intermediate_ca_certificate_checksum}")
    log('intermediate ca private key checksum: '
        f"{intermediate_ca_private_key_checksum}")

    # get intermediate ca remote checksum
    intermediate_ca_checksum = \
        _get_keypair_checksum(
            intermediate_ca_certificate_checksum,
            intermediate_ca_private_key_checksum)

    log(f"intermediate ca checksum: {intermediate_ca_checksum}")

    # get intermediate ca file paths
    intermediate_ca_certificate_file_path = \
        _get_repository_file_path(
            repository_dir,
            INTERMEDIATE_CA_CERTIFICATE_FILE_NAME)
    intermediate_ca_private_key_file_path = \
        _get_repository_file_path(
            repository_dir,
            INTERMEDIATE_CA_PRIVATE_KEY_FILE_NAME)

    # download intermediate ca keypair
    _download_s3_object_to_path(
        intermediate_ca_certificate,
        intermediate_ca_certificate_checksum,
        intermediate_ca_certificate_file_path)
    _download_s3_object_to_path(
        intermediate_ca_private_key,
        intermediate_ca_private_key_checksum,
        intermediate_ca_private_key_file_path)

    # create leaf key pair
    leaf_file_prefix = input_payload['source']['leaf_name']
    lib.cfssl.create_leaf(
        input_payload,
        repository_dir,
        leaf_file_prefix,
        INTERMEDIATE_CA_CERTIFICATE_FILE_NAME,
        INTERMEDIATE_CA_PRIVATE_KEY_FILE_NAME)

    # get leaf file paths
    leaf_certificate_file_name = f"{leaf_file_prefix}.pem"
    leaf_certificate_file_path = \
        _get_repository_file_path(
            repository_dir,
            leaf_certificate_file_name)
    leaf_private_key_file_name = f"{leaf_file_prefix}-key.pem"
    leaf_private_key_file_path = \
        _get_repository_file_path(
            repository_dir,
            leaf_private_key_file_name)

    # get leaf local checksums
    leaf_certificate_checksum = \
        _hash_file(leaf_certificate_file_path)
    leaf_private_key_checksum = \
        _hash_file(leaf_private_key_file_path)

    log('leaf certificate checksum: '
        f"{leaf_certificate_checksum}")
    log('leaf private key checksum: '
        f"{leaf_private_key_checksum}")

    # get leaf local checksum
    leaf_checksum = \
        _get_keypair_checksum(
            leaf_certificate_checksum,
            leaf_private_key_checksum)

    log(f"leaf checksum: {leaf_checksum}")

    # create leaf s3 objects
    leaf_certificate = \
        _get_s3_object(
            input_payload,
            s3_resource,
            leaf_certificate_file_name)
    leaf_private_key = \
        _get_s3_object(
            input_payload,
            s3_resource,
            leaf_private_key_file_name)

    # upload certificate
    _upload_s3_object_to_path(
        leaf_certificate,
        leaf_certificate_checksum,
        leaf_certificate_file_path)

    # upload private key
    _upload_s3_object_to_path(
        leaf_private_key,
        leaf_private_key_checksum,
        leaf_private_key_file_path)

    # create output payload
    output_payload = _create_out_payload(
        input_payload,
        leaf_checksum,
        leaf_certificate_file_name,
        leaf_certificate_checksum,
        leaf_private_key_file_name,
        leaf_private_key_checksum)

    # write output
    _write_payload(output_payload)
