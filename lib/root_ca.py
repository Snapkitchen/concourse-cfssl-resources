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
