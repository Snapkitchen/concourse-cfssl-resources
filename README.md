# concourse-cfssl-resources

## concourse-cfssl-baseline

baseline for each concourse cfssl resource

includes:

- bash (4.4.19)
- git (2.18.0)
- go (1.10.1)
- python3 (3.6.6)
- cfssl

also includes pip packages in [requirements.txt](requirements.txt)

## concourse-cfssl-root-ca-resource

creates and gets root ca using cfssl

### source configuration

- `bucket_name`: _required_. the name of the bucket.

- `access_key_id`: _required_. the aws access key id to use when accessing the bucket

- `secret_access_key`: _required_. the aws secret access key to use when accessing the bucket

- `region_name`: _required_. the region the bucket is in.

- `prefix`: _optional_. the prefix path to prepend to the cfssl files. e.g. `prefix: my/prefix/path` will result in a root ca cert file path of `<bucket>/my/prefix/path/root-ca.pem` default: none

- `endpoint`: _optional_. custom endpoint for using S3 compatible provider.

- `disable_ssl`: _optional_. disable SSL for the endpoint, useful for S3 compatible providers without SSL.

### behavior

#### `check`: check for root ca

#### `in`: fetch root ca certificate and private key

fetches the certificate and/or private key file for a root ca

the following files will be places in the destination, based on parameters:

- `/root-ca.pem`: the root ca certificate file

- `/root-ca-key.pem`: the root ca private key file

**parameters**

- `save_certificate`: _optional_. save the certificate file to disk. default: `true`

- `save_private_key`: _optional_. save the private key file to disk. default: `false`

#### `out`: create root ca

creates a new root ca certificate and private key

**parameters**

- `expiry`: _optional._ the expiration length to use for the ca (a time duration in the form understood by go's time package). e.g. `43800h` for 5 years. default value is cfssl's default.

## concourse-cfssl-intermediate-ca-resource

TODO

## concourse-cfssl-server-cert-resource

TODO

## concourse-cfssl-client-cert-resource

TODO

## development

install python 3.6 and requirements from `requirements-dev.txt`

install cfssl

`.vscode/settings.json` will enable linters in vscode

`.env` sets `PYTHONPATH` to allow ide to resolve lib file path

## building

builds are handled automatically by [docker hub](https://hub.docker.com)

the baseline image is built upon every commit to master

once that is built, the resource images are automatically triggered and built

## license

see [LICENSE](LICENSE)
