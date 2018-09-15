# local
import lib.common


# =============================================================================
#
# constants
#
# =============================================================================

ROOT_CA_CERT_FILE_NAME = 'root-ca.pem'
ROOT_CA_PRIVATE_KEY_FILE_NAME = 'root-ca-key.pem'


# =============================================================================
#
# general
#
# =============================================================================

# =============================================================================
# checksum
# =============================================================================
def checksum(
        root_ca_cert_checksum,
        root_ca_private_key_checksum) -> str:
    # ensure deterministic ordering of hash list for root ca
    return lib.common.hash_list([root_ca_cert_checksum,
                                 root_ca_private_key_checksum])


# =============================================================================
#
# in
#
# =============================================================================

# =============================================================================
# do_in
# =============================================================================
def do_in() -> None:
    # read the concourse input payload from stdin
    input_config = lib.common.read_concourse_input_payload()

# read input payload from stdin
# first argument ($1) contains destination directory

# check s3 for keys
# check the checksums in s3
# calculate combined checksum
# if combined checksum matces, download copies locally
# if they don't match, throw an error (version not found)
