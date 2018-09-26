# stdlib
import json
import os
import subprocess

# local
import lib.concourse
from lib.log import log


# =============================================================================
#
# constants
#
# =============================================================================

CFSSL_WORKSPACE_DIR_PATH = '/tmp/cfssl'
CFSSL_BIN_FILE_PATH = '/root/go/bin/cfssl'
CFSSLJSON_BIN_FILE_PATH = '/root/go/bin/cfssljson'
ROOT_CA_DEFAULT_KEY_ALGORITHM = 'ecdsa'
ROOT_CA_DEFAULT_KEY_SIZE = 256
ROOT_CA_DEFAULT_EXPIRY = '87600h'
INTERMEDIATE_CA_DEFAULT_KEY_ALGORITHM = 'ecdsa'
INTERMEDIATE_CA_DEFAULT_KEY_SIZE = 256
INTERMEDIATE_CA_DEFAULT_EXPIRY = '43800h'


# =============================================================================
#
# functions
#
# =============================================================================


# =============================================================================
# _run
# =============================================================================
def _run(bin: str, *args: str, input=None) -> subprocess.CompletedProcess:
    command_output = subprocess.run([bin] + list(args),
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    encoding='utf-8',
                                    input=input)
    # log stderr if present
    if command_output.stderr:
        log(f"{bin} stderr:")
        log(command_output.stderr)

    # raise if non-zero
    command_output.check_returncode()

    # return the command output
    return command_output


# =============================================================================
# _cfssl
# =============================================================================
def _cfssl(*args: str, input=None) -> subprocess.CompletedProcess:
    return _run(CFSSL_BIN_FILE_PATH,
                *args,
                input=input)


# =============================================================================
# _cfssljson
# =============================================================================
def _cfssljson(*args: str, input=None) -> subprocess.CompletedProcess:
    return _run(CFSSLJSON_BIN_FILE_PATH,
                *args,
                input=input)


# =============================================================================
# _create_root_ca_csr
# =============================================================================
def _create_root_ca_csr() -> dict:
    # create the base request
    signing_request: dict = {
        'CN': lib.concourse.payload['params']['CN'],
        'key': {
            'algo': ROOT_CA_DEFAULT_KEY_ALGORITHM,
            'size': ROOT_CA_DEFAULT_KEY_SIZE
        },
        'ca': {
            'expiry': ROOT_CA_DEFAULT_EXPIRY,
            'pathlen': 1
        },
        'names': []
    }
    # set key properties from payload, if present
    if 'key' in lib.concourse.payload['params']:
        # key algorithm
        signing_request['key']['algo'] = \
            lib.concourse.payload['params']['key'].get(
                'algo', ROOT_CA_DEFAULT_KEY_ALGORITHM)
        # key size
        signing_request['key']['size'] = \
            lib.concourse.payload['params']['key'].get(
                'size', ROOT_CA_DEFAULT_KEY_SIZE)
    # set ca properties from payload, if present
    if 'ca' in lib.concourse.payload['params']:
        # expiry
        signing_request['ca']['expiry'] = \
            lib.concourse.payload['params']['ca'].get(
                'expiry', ROOT_CA_DEFAULT_EXPIRY)
    # set names from payload, if present
    if 'names' in lib.concourse.payload['params']:
        signing_request['names'] = lib.concourse.payload['params']['names']
    # log config for debugging
    log("root ca signing request:")
    log(json.dumps(signing_request, indent=4))
    # return signing request
    return signing_request


# =============================================================================
# create_root_ca
# =============================================================================
def create_root_ca(destination_dir_path,
                   file_prefix) -> None:
    # create root ca csr
    root_ca_csr = _create_root_ca_csr()

    # generate the root ca
    cfssl_output = _cfssl('gencert',
                          '-initca=true',
                          '-loglevel=0',
                          '-',
                          input=json.dumps(root_ca_csr))

    # capture the output to file
    _cfssljson('-bare',
               os.path.join(destination_dir_path,
                            file_prefix),
               input=cfssl_output.stdout)


# =============================================================================
# _create_intermediate_ca_csr
# =============================================================================
def _create_intermediate_ca_csr() -> dict:
    # create the base request
    signing_request: dict = {
        'key': {
            'algo': INTERMEDIATE_CA_DEFAULT_KEY_ALGORITHM,
            'size': INTERMEDIATE_CA_DEFAULT_KEY_SIZE
        },
        'names': []
    }
    # set key properties from payload, if present
    if 'key' in lib.concourse.payload['params']:
        # key algorithm
        signing_request['key']['algo'] = \
            lib.concourse.payload['params']['key'].get(
                'algo', INTERMEDIATE_CA_DEFAULT_KEY_ALGORITHM)
        # key size
        signing_request['key']['size'] = \
            lib.concourse.payload['params']['key'].get(
                'size', INTERMEDIATE_CA_DEFAULT_KEY_SIZE)
    # set ca properties from payload, if present
    if 'ca' in lib.concourse.payload['params']:
        # expiry
        signing_request['ca']['expiry'] = \
            lib.concourse.payload['params']['ca'].get(
                'expiry', INTERMEDIATE_CA_DEFAULT_EXPIRY)
    # set names from payload, if present
    if 'names' in lib.concourse.payload['params']:
        signing_request['names'] = lib.concourse.payload['params']['names']
    # log config for debugging
    log("intermediate ca signing request:")
    log(json.dumps(signing_request, indent=4))
    # return signing request
    return signing_request


# =============================================================================
# create_intermediate_ca
# =============================================================================
def create_intermediate_ca(repository_dir_path,
                           file_prefix,
                           root_ca_certificate_file_name,
                           root_ca_private_key_file_name) -> None:
    # create intermediate ca csr
    intermediate_ca_csr = _create_intermediate_ca_csr()
