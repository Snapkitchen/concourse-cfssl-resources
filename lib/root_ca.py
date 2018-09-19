# stdlib
import os.path
import sys

# local
import lib.aws
import lib.concourse
import lib.hash
from lib.log import log


# =============================================================================
#
# constants
#
# =============================================================================

CERT_FILE_NAME = 'root-ca.pem'
PRIVATE_KEY_FILE_NAME = 'root-ca-key.pem'


# =============================================================================
#
# functions
#
# =============================================================================

# =============================================================================
# _get_certificate_file_path
# =============================================================================
def _get_certificate_file_path() -> str:
    return os.path.join(sys.argv[1], CERT_FILE_NAME)


# =============================================================================
# _get_private_key_file_path
# =============================================================================
def _get_private_key_file_path() -> str:
    return os.path.join(sys.argv[1], PRIVATE_KEY_FILE_NAME)


# =============================================================================
# _certificate_is_downloaded
# =============================================================================
def _certificate_is_downloaded() -> bool:
    return os.path.isfile(_get_certificate_file_path())


# =============================================================================
# _private_key_is_downloaded
# =============================================================================
def _private_key_is_downloaded() -> bool:
    return os.path.isfile(_get_private_key_file_path())


# =============================================================================
# _get_certificate_checksum
# =============================================================================
def _get_certificate_checksum() -> str:
    return lib.aws.get_s3_object_checksum(certificate)


# =============================================================================
# _get_private_key_checksum
# =============================================================================
def _get_private_key_checksum() -> str:
    return lib.aws.get_s3_object_checksum(private_key)


# =============================================================================
# _get_downloaded_certificate_checksum()
# =============================================================================
def _get_downloaded_certificate_checksum() -> str:
    return lib.hash.hash_file(_get_certificate_file_path())


# =============================================================================
# _get_downloaded_private_key_checksum()
# =============================================================================
def _get_downloaded_private_key_checksum() -> str:
    return lib.hash.hash_file(_get_private_key_file_path())


# =============================================================================
# _should_download_certificate
# =============================================================================
def _should_download_certificate() -> bool:
    if 'params' in lib.concourse.payload:
        return lib.concourse.payload['params'].get('save_certificate') is True
    else:
        return False


# =============================================================================
# _should_download_private_key
# =============================================================================
def _should_download_private_key() -> bool:
    if 'params' in lib.concourse.payload:
        return lib.concourse.payload['params'].get('save_private_key') is True
    else:
        return False


# =============================================================================
# _download_certificate_if_requested
# =============================================================================
def _download_certificate_if_requested() -> None:
    if _should_download_certificate():
        _download_certificate()


# =============================================================================
# _download_private_key_if_requested
# =============================================================================
def _download_private_key_if_requested() -> None:
    if _should_download_private_key():
        _download_private_key()


# =============================================================================
# _download_certificate
# =============================================================================
def _download_certificate() -> None:
    lib.aws.download_s3_object_to_path(
        certificate,
        _get_certificate_checksum(),
        _get_certificate_file_path())


# =============================================================================
# _download_private_key
# =============================================================================
def _download_private_key() -> None:
    lib.aws.download_s3_object_to_path(
        private_key,
        _get_private_key_checksum(),
        _get_private_key_file_path())


# =============================================================================
# _get_checksum
# =============================================================================
def _get_checksum() -> str:
    return lib.hash.hash_list([
        _get_certificate_checksum(),
        _get_private_key_checksum()])


# =============================================================================
# _requested_checksum_is_available
# =============================================================================
def _requested_checksum_is_available() -> bool:
    # get requested checksum from concourse payload
    requested_checksum = lib.concourse.payload['version']['checksum']
    log(f"requested root ca checksum: {requested_checksum}")
    # get current checksum
    current_checksum = _get_checksum()
    log(f"current root ca checksum: {current_checksum}")
    # compare requested checksum to current checksum
    return requested_checksum == current_checksum


# =============================================================================
# _get_certificate_concourse_metadata
# =============================================================================
def _get_certificate_concourse_metadata() -> list:
    return [
        {
            'name': 'certificate_file_name',
            'value': CERT_FILE_NAME
        },
        {
            'name': 'certificate_checksum',
            'value': _get_downloaded_certificate_checksum()
        }]


# =============================================================================
# _get_private_key_concourse_metadata
# =============================================================================
def _get_private_key_concourse_metadata() -> list:
    return [
        {
            'name': 'private_key_file_name',
            'value': PRIVATE_KEY_FILE_NAME
        },
        {
            'name': 'private_key_checksum',
            'value': _get_downloaded_private_key_checksum()
        }]


# =============================================================================
# _create_concourse_check_payload
# =============================================================================
def _create_concourse_check_payload(checksum: str) -> list:
    return [{'checksum': checksum}]


# =============================================================================
# _write_concourse_check_payload
# =============================================================================
def _write_concourse_check_payload() -> None:
    # get checksum,
    # create a concourse check payload,
    # and write it out
    lib.concourse.write_payload(
        _create_concourse_check_payload(
            _get_checksum()))


# =============================================================================
# _create_concourse_in_payload
# =============================================================================
def _create_concourse_in_payload() -> dict:
    in_payload: dict = {
        'version': {
            'checksum': lib.concourse.payload['version']['checksum']
        },
        'metadata': []
    }
    if _certificate_is_downloaded():
        in_payload['metadata'].extend(_get_certificate_concourse_metadata())
    if _private_key_is_downloaded():
        in_payload['metadata'].extend(_get_private_key_concourse_metadata())
    return in_payload


# =============================================================================
# _write_concourse_in_payload
# =============================================================================
def _write_concourse_in_payload() -> None:
    lib.concourse.write_payload(_create_concourse_in_payload())


# =============================================================================
# do_check
# =============================================================================
def do_check() -> None:
    _write_concourse_check_payload()


# =============================================================================
# do_in
# =============================================================================
def do_in() -> None:
    # compare the root ca checksum vs the requested checksum
    if _requested_checksum_is_available():
        _download_certificate_if_requested()
        _download_private_key_if_requested()
        _write_concourse_in_payload()
    else:
        # cannot continue if checksum is unavailable
        raise ValueError(f"requested checksum is unavailable")


# =============================================================================
#
# properties
#
# =============================================================================

# =============================================================================
# certificate
# =============================================================================
certificate = lib.aws.get_s3_object(CERT_FILE_NAME)

# =============================================================================
# private_key
# =============================================================================
private_key = lib.aws.get_s3_object(PRIVATE_KEY_FILE_NAME)
