# stdlib
import json
import sys

# pip
import boto3

# =============================================================================
#
# constants
#
# =============================================================================

AWS_DEFAULT_REGION = 'us-east-1'
ROOT_CA_CERT_FILE_NAME = 'root-ca.pem'
ROOT_CA_PRIVATE_KEY_FILE_NAME = 'root-ca-key.pem'


# =============================================================================
#
# general
#
# =============================================================================

# =============================================================================
# _read_stdin_as_json_into_dict
# =============================================================================
def _read_stdin_as_json_into_dict() -> dict:
    return json.load(sys.stdin)


# =============================================================================
# hello_world
# =============================================================================
def hello_world() -> None:
    print('hello world', file=sys.stderr)


# =============================================================================
#
# boto3
#
# =============================================================================

# =============================================================================
# _get_boto3_session
# =============================================================================
def _get_boto3_session(config: dict) -> boto3.session.Session:
    return boto3.session.Session(
        aws_access_key_id=config.get('access_key_id'),
        aws_secret_access_key=config.get('secret_access_key'),
        region_name=config.get('region_name', AWS_DEFAULT_REGION)
    )


# =============================================================================
# _get_boto3_session
# =============================================================================
def _get_s3_resource(
        session: boto3.session.Session,
        config: dict) -> boto3.resources.base.ServiceResource:
    return session.resource('s3')


# =============================================================================
#
# check
#
# =============================================================================

# =============================================================================
# do_check
# =============================================================================
def do_check() -> None:
    # read the concourse input config from stdin
    input_config = _read_stdin_as_json_into_dict()
    # get the source config section of the input config
    source_config = input_config['source']
    # create the boto3 session using auth from source config
    boto3_session = _get_boto3_session(source_config)
    # create the s3 resource using the boto3 session and source config
    s3_resource = _get_s3_resource(boto3_session, source_config)
    # get the bucket
    bucket = s3_resource.Bucket(source_config['bucket'])
    bucket.load()

# check for existence of root-ca.pem and root-ca-key.pem in s3
# check if they have checksums in their metadata (sha256: value)
# retrieve the checksums
# calculate a new checksum based on the combination of the retrieved checksums
# return that checksum as the version
