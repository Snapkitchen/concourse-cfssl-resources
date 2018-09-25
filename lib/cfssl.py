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


# =============================================================================
#
# functions
#
# =============================================================================


# =============================================================================
# _run
# =============================================================================
def _run(bin: str, *args: str, input=None) -> subprocess.CompletedProcess:
    return subprocess.run([bin] + list(args),
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          encoding='utf-8',
                          input=input)


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
# _create_root_ca_config
# =============================================================================
def _create_root_ca_config() -> dict:
    # create the base config
    cfssl_config: dict = {
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
        cfssl_config['key']['algo'] = \
            lib.concourse.payload['params']['key'].get(
                'algo', ROOT_CA_DEFAULT_KEY_ALGORITHM)
        # key size
        cfssl_config['key']['size'] = \
            lib.concourse.payload['params']['key'].get(
                'size', ROOT_CA_DEFAULT_KEY_SIZE)
    # set ca properties from payload, if present
    if 'ca' in lib.concourse.payload['params']:
        # expiry
        cfssl_config['ca']['expiry'] = \
            lib.concourse.payload['params']['ca'].get(
                'expiry', ROOT_CA_DEFAULT_EXPIRY)
    # set names from payload, if present
    if 'names' in lib.concourse.payload['params']:
        cfssl_config['names'] = lib.concourse.payload['params']['names']
    # return config
    return cfssl_config


# =============================================================================
# create_root_ca
# =============================================================================
def create_root_ca(destination_dir_path,
                   file_prefix) -> None:
    # create root ca config
    root_ca_config = _create_root_ca_config()

    # log config for debugging
    log("root_ca_config:")
    log(json.dumps(root_ca_config, indent=4))

    # generate the root ca
    cfssl_output = _cfssl('gencert',
                          '-initca=true',
                          '-loglevel=0',
                          '-',
                          input=json.dumps(root_ca_config))

    # log stderr if present
    if cfssl_output.stderr:
        log("cfssl stderr:")
        log(cfssl_output.stderr)

    # raise if non-zero
    cfssl_output.check_returncode()

    # capture the output to file
    cfssljson_output = _cfssljson('-bare',
                                  os.path.join(destination_dir_path,
                                               file_prefix),
                                  input=cfssl_output.stdout)
    # log stderr if present
    if cfssljson_output.stderr:
        log("cfssljson stderr:")
        log(cfssljson_output.stderr)

    # raise if non-zero
    cfssljson_output.check_returncode()
