# stdlib
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from typing import List

# local
import lib.concourse
from lib.log import log

#
# renew root:
#

# cfssl gencert -renewca -ca root-ca.pem -ca-key root-ca-key.pem | cfssljson -bare root-ca

#
# renew intermediate:
#

# cfssl gencsr -key intermediate-ca-key.pem -cert intermediate-ca.pem | cfssljson -bare intermediate-ca
# cfssl sign -ca root-ca.pem -ca-key root-ca-key.pem -config config.json -profile ca intermediate-ca.csr | cfssljson -bare intermediate-ca

#
# renew leaf:
#

# cfssl gencsr -key server-key.pem -cert server.pem | cfssljson -bare server
# cfssl sign -ca intermediate-ca.pem -ca-key intermediate-ca-key.pem -config config.json -profile leaf server.csr | cfssljson -bare server

# =============================================================================
#
# constants
#
# =============================================================================

CFSSL_DATETIME_FORMAT: str = '%Y-%m-%dT%H:%M:%S%z'
CFSSL_WORKSPACE_DIR_PATH: str = '/tmp/cfssl'
CFSSL_BIN_FILE_PATH: str = '/root/go/bin/cfssl'
CFSSLJSON_BIN_FILE_PATH: str = '/root/go/bin/cfssljson'
ROOT_CA_DEFAULT_KEY_ALGORITHM: str = 'rsa'
ROOT_CA_DEFAULT_KEY_SIZE: int = 2048
ROOT_CA_DEFAULT_EXPIRY: str = '87600h'
INTERMEDIATE_CA_DEFAULT_KEY_ALGORITHM: str = 'rsa'
INTERMEDIATE_CA_DEFAULT_KEY_SIZE: int = 2048
INTERMEDIATE_CA_DEFAULT_EXPIRY: str = '43800h'
INTERMEDIATE_CA_SIGNING_CONFIG_FILE_NAME: str = 'intermediate-ca-config.json'
LEAF_DEFAULT_KEY_ALGORITHM: str = 'rsa'
LEAF_DEFAULT_KEY_SIZE: int = 2048
LEAF_DEFAULT_EXPIRY: str = '8760h'
LEAF_DEFAULT_USAGES: List[str] = \
    ['signing',
     'key encipherment',
     'server auth',
     'client auth']
LEAF_SIGNING_CONFIG_FILE_NAME: str = 'leaf-config.json'


# =============================================================================
#
# private exe functions
#
# =============================================================================

# =============================================================================
# _run
# =============================================================================
def _run(bin: str, *args: str, input=None) -> subprocess.CompletedProcess:
    command_output = subprocess.run([bin] + list(args),
                                    capture_output=True,
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
#
# private pki functions
#
# =============================================================================

# =============================================================================
# _create_root_ca_signing_request
# =============================================================================
def _create_root_ca_signing_request(payload: dict) -> dict:
    # create the base request
    signing_request: dict = {
        'CN': payload['params']['CN'],
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
    if 'key' in payload['params']:
        # key algorithm
        signing_request['key']['algo'] = \
            payload['params']['key'].get(
                'algo', ROOT_CA_DEFAULT_KEY_ALGORITHM)
        # key size
        signing_request['key']['size'] = \
            payload['params']['key'].get(
                'size', ROOT_CA_DEFAULT_KEY_SIZE)
    # set ca properties from payload, if present
    if 'ca' in payload['params']:
        # expiry
        signing_request['ca']['expiry'] = \
            payload['params']['ca'].get(
                'expiry', ROOT_CA_DEFAULT_EXPIRY)
    # set names from payload, if present
    if 'names' in payload['params']:
        signing_request['names'] = payload['params']['names']
    # log request for debugging
    log("root ca signing request:")
    log(json.dumps(signing_request, indent=4))
    # return signing request
    return signing_request


# =============================================================================
# _create_intermediate_ca_signing_config
# =============================================================================
def _create_intermediate_ca_signing_config(payload: dict) -> dict:
    # create the base signing config
    signing_config: dict = {
        'signing': {
            'profiles': {
                'ca': {
                    'expiry': INTERMEDIATE_CA_DEFAULT_EXPIRY,
                    'usages': [
                        'cert sign',
                        'crl sign'
                    ],
                    'ca_constraint': {
                        'is_ca': True,
                        'max_path_len': 0,
                        'max_path_len_zero': True
                    }
                }
            }
        }
    }
    # set ca properties from payload, if present
    if 'ca' in payload['params']:
        # expiry
        signing_config['signing']['profiles']['ca']['expiry'] = \
            payload['params']['ca'].get(
                'expiry', INTERMEDIATE_CA_DEFAULT_EXPIRY)
    # log config for debugging
    log("intermediate ca signing config:")
    log(json.dumps(signing_config, indent=4))
    return signing_config


# =============================================================================
# _create_intermediate_ca_signing_request
# =============================================================================
def _create_intermediate_ca_signing_request(payload: dict) -> dict:
    # create the base request
    signing_request: dict = {
        'key': {
            'algo': INTERMEDIATE_CA_DEFAULT_KEY_ALGORITHM,
            'size': INTERMEDIATE_CA_DEFAULT_KEY_SIZE
        },
        'names': []
    }
    # set key properties from payload, if present
    if 'key' in payload['params']:
        # key algorithm
        signing_request['key']['algo'] = \
            payload['params']['key'].get(
                'algo', INTERMEDIATE_CA_DEFAULT_KEY_ALGORITHM)
        # key size
        signing_request['key']['size'] = \
            payload['params']['key'].get(
                'size', INTERMEDIATE_CA_DEFAULT_KEY_SIZE)
    # set names from payload, if present
    if 'names' in payload['params']:
        signing_request['names'] = payload['params']['names']
    # log request for debugging
    log("intermediate ca signing request:")
    log(json.dumps(signing_request, indent=4))
    # return signing request
    return signing_request


# =============================================================================
# _create_leaf_signing_config
# =============================================================================
def _create_leaf_signing_config(payload: dict) -> dict:
    # create the base signing config
    signing_config: dict = {
        'signing': {
            'profiles': {
                'leaf': {
                    'expiry': LEAF_DEFAULT_EXPIRY,
                    'usages': LEAF_DEFAULT_USAGES
                }
            }
        }
    }
    # set leaf properties from payload, if present
    if 'leaf' in payload['params']:
        # expiry
        signing_config['signing']['profiles']['leaf']['expiry'] = \
            payload['params']['leaf'].get(
                'expiry', LEAF_DEFAULT_EXPIRY)
        # usages
        signing_config['signing']['profiles']['leaf']['usages'] = \
            payload['params']['leaf'].get(
                'usages', LEAF_DEFAULT_USAGES)
    # log config for debugging
    log("leaf signing config:")
    log(json.dumps(signing_config, indent=4))
    return signing_config


# =============================================================================
# _create_leaf_signing_request
# =============================================================================
def _create_leaf_signing_request(payload: dict) -> dict:
    # create the base request
    signing_request: dict = {
        'key': {
            'algo': LEAF_DEFAULT_KEY_ALGORITHM,
            'size': LEAF_DEFAULT_KEY_SIZE
        },
        'names': []
    }
    # set key properties from payload, if present
    if 'key' in payload['params']:
        # key algorithm
        signing_request['key']['algo'] = \
            payload['params']['key'].get(
                'algo', LEAF_DEFAULT_KEY_ALGORITHM)
        # key size
        signing_request['key']['size'] = \
            payload['params']['key'].get(
                'size', LEAF_DEFAULT_KEY_SIZE)
    # set names from payload, if present
    if 'names' in payload['params']:
        signing_request['names'] = payload['params']['names']
    # log request for debugging
    log("leaf signing request:")
    log(json.dumps(signing_request, indent=4))
    # return signing request
    return signing_request


# =============================================================================
#
# public utility functions
#
# =============================================================================

# =============================================================================
# get_certificate_info
# =============================================================================
def get_certificate_info(
        certificate_file_path: str) -> dict:
    # get certinfo json
    certinfo_output = _cfssl('certinfo', '-cert', certificate_file_path)
    # return parsed json
    return json.loads(certinfo_output.stdout)


# =============================================================================
# get_certificate_issue_date
# =============================================================================
def get_certificate_issue_date(
        certificate_info: dict) -> datetime:
    return datetime.strptime(
        certificate_info['not_before'],
        CFSSL_DATETIME_FORMAT)


# =============================================================================
# get_certificate_expiration_date
# =============================================================================
def get_certificate_expiration_date(
        certificate_info: dict) -> datetime:
    return datetime.strptime(
        certificate_info['not_after'],
        CFSSL_DATETIME_FORMAT)


# =============================================================================
# get_duration_until_certificate_expiration
# =============================================================================
def get_duration_until_certificate_expiration(
        certificate_expiration_date: datetime) -> timedelta:
    return certificate_expiration_date - datetime.now(timezone.utc)


# =============================================================================
#
# public lifecycle functions
#
# =============================================================================

# =============================================================================
# create_root_ca
# =============================================================================
def create_root_ca(
        payload: dict,
        destination_dir_path: str,
        file_prefix: str) -> None:
    # create root ca signing request
    root_ca_signing_request = _create_root_ca_signing_request(payload)

    # generate the root ca
    cfssl_output = _cfssl('gencert',
                          '-initca=true',
                          '-loglevel=0',
                          '-',
                          input=json.dumps(root_ca_signing_request))

    # capture the output to file
    _cfssljson('-bare',
               os.path.join(destination_dir_path,
                            file_prefix),
               input=cfssl_output.stdout)


# =============================================================================
# create_intermediate_ca
# =============================================================================
def create_intermediate_ca(
        payload: dict,
        repository_dir_path: str,
        file_prefix: str,
        root_ca_certificate_file_name: str,
        root_ca_private_key_file_name: str) -> None:
    # create intermediate ca signing request
    intermediate_ca_signing_request = \
        _create_intermediate_ca_signing_request(payload)
    # create intermediate ca signing config
    intermediate_ca_signing_config = \
        _create_intermediate_ca_signing_config(payload)
    # write intermediate ca signing config to file
    intermediate_ca_signing_config_file_path = \
        os.path.join(repository_dir_path,
                     INTERMEDIATE_CA_SIGNING_CONFIG_FILE_NAME)
    with open(intermediate_ca_signing_config_file_path, 'w') \
            as signing_config_file:
        json.dump(intermediate_ca_signing_config, signing_config_file)
    # generate and sign the intermediate ca
    root_ca_certificate_file_path = \
        os.path.join(
            repository_dir_path,
            root_ca_certificate_file_name)
    root_ca_private_key_file_path = \
        os.path.join(
            repository_dir_path,
            root_ca_private_key_file_name)
    intermediate_ca_common_name = payload['params']['CN']
    cfssl_output = _cfssl(
        'gencert',
        f"-ca={root_ca_certificate_file_path}",
        f"-ca-key={root_ca_private_key_file_path}",
        f"-config={intermediate_ca_signing_config_file_path}",
        '-profile=ca',
        f"-cn={intermediate_ca_common_name}"
        '-loglevel=0',
        '-',
        input=json.dumps(intermediate_ca_signing_request))
    # capture the output to file
    _cfssljson('-bare',
               os.path.join(repository_dir_path,
                            file_prefix),
               input=cfssl_output.stdout)


# =============================================================================
# create_leaf
# =============================================================================
def create_leaf(
        payload: dict,
        repository_dir_path: str,
        file_prefix: str,
        intermediate_ca_certificate_file_name: str,
        intermediate_ca_private_key_file_name: str) -> None:
    # create leaf signing request
    leaf_signing_request = \
        _create_leaf_signing_request(payload)
    # create leaf signing config
    leaf_signing_config = \
        _create_leaf_signing_config(payload)
    # write leaf signing config to file
    leaf_signing_config_file_path = \
        os.path.join(repository_dir_path,
                     LEAF_SIGNING_CONFIG_FILE_NAME)
    with open(leaf_signing_config_file_path, 'w') \
            as signing_config_file:
        json.dump(leaf_signing_config, signing_config_file)
    # generate and sign the leaf
    intermediate_ca_certificate_file_path = \
        os.path.join(
            repository_dir_path,
            intermediate_ca_certificate_file_name)
    intermediate_ca_private_key_file_path = \
        os.path.join(
            repository_dir_path,
            intermediate_ca_private_key_file_name)
    leaf_common_name = payload['params']['CN']
    cfssl_gencert_args = [
        f"-ca={intermediate_ca_certificate_file_path}",
        f"-ca-key={intermediate_ca_private_key_file_path}",
        f"-config={leaf_signing_config_file_path}",
        '-profile=leaf',
        f"-cn={leaf_common_name}"
    ]
    # add hosts arg, if present
    # converts list to comma separated list
    if 'leaf' in payload['params']:
        if 'hosts' in payload['params']['leaf']:
            cfssl_gencert_args.append(
                '-hostname='
                f"\"{','.join(payload['params']['leaf']['hosts'])}\"")
    cfssl_output = _cfssl(
        'gencert',
        *cfssl_gencert_args,
        '-loglevel=0',
        '-',
        input=json.dumps(leaf_signing_request))
    # capture the output to file
    _cfssljson('-bare',
               os.path.join(repository_dir_path,
                            file_prefix),
               input=cfssl_output.stdout)


# =============================================================================
# renew_root_certificate
# =============================================================================
def renew_root_certificate(
    repository_dir_path: str,
    file_prefix: str,
    root_ca_certificate_file_name: str,
    root_ca_private_key_file_name: str
) -> None:
    # determine file paths
    root_ca_certificate_file_path = \
        os.path.join(repository_dir_path,
                     root_ca_certificate_file_name)
    root_ca_private_key_file_path = \
        os.path.join(repository_dir_path,
                     root_ca_private_key_file_name)
    # renew the ca certificate using the
    # existing certificate and private key
    cfssl_output = _cfssl(
        'gencert',
        '-renewca',
        '-ca',
        root_ca_certificate_file_path,
        '-ca-key',
        root_ca_private_key_file_path,
        '-loglevel=0')
    # capture the output to file
    _cfssljson('-bare',
               os.path.join(repository_dir_path,
                            file_prefix),
               input=cfssl_output.stdout)
