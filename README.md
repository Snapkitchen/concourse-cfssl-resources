# concourse-cfssl-resources

## concourse-cfssl-baseline

baseline for each concourse cfssl resource

includes:

- bash (4.4.19)
- git (2.18.0)
- go (1.10.1)
- python3 (3.6.6)
- cfssl

also includes pip packages in `requirements.txt`

## concourse-cfssl-root-ca-resource

creates and gets root ca using cfssl

### source configuration

- `bucket`: _required_. the name of the bucket.

- `access_key_id`: _optional_. the aws access key id to use when accessing the bucket

- `secret_access_key`: _optional_. the aws secret access key to use when accessing the bucket

- `region_name`: _optional_. the region the bucket is in. defaults to `us-east-1`

### behavior

#### `check`: check for root ca

#### `in`: fetch root ca certificate and private key

fetches the certificate and/or private key file for a root ca

the following files will be places in the destination, based on parameters:

- `/root-ca.pem`: the root ca certificate file

- `/root-ca-key.pem`: the root ca private key file

**parameters**

- `certificate`: _optional_. fetch the certificate file. default: `true`

- `private_key`: _optional_. fetch the private key file. default: `false`

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
