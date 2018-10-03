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

- `prefix`: _optional_. the prefix path to prepend to the cfssl files. e.g. `prefix: my/prefix/path` will result in a root ca cert file path of `<bucket>/my/prefix/path/root-ca.pem` default: `null`

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

note: parameters are mostly 1:1 analogous to their cfssl counterparts

see cfssl documentation for best practices and examples

**parameters**

- `CN`: _required_. the certificate common name

- `key`: _optional_. the key parameters

	- `algo`: _optional_. algorithm. default: `rsa`

	- `size`: _optional_. size. default: `2048`

- `ca`: _optional_. the ca parameters

	- `expiry`: _optional_. the expiration length to use for the ca (a time duration in the form understood by go's time package). default: `87600h`

- `names`: _optional_. array containing single dict with fields used when signing

	- `C`: _optional_. country code

	- `L`: _optional_. city / locality

	- `O`: _optional_. organization

	- `OU`: _optional_. organizational unit

	- `ST`: _optional_. state

## concourse-cfssl-intermediate-ca-resource

creates and gets intermediate ca using cfssl

### source configuration

- `bucket_name`: _required_. the name of the bucket.

- `access_key_id`: _required_. the aws access key id to use when accessing the bucket

- `secret_access_key`: _required_. the aws secret access key to use when accessing the bucket

- `region_name`: _required_. the region the bucket is in.

- `prefix`: _optional_. the prefix path to prepend to the cfssl files. e.g. `prefix: my/prefix/path` will result in an intermediate ca cert file path of `<bucket>/my/prefix/path/intermediate-ca.pem` default: `null`  
  
  note: this path must also contain the root ca certificate and private key under `root-ca.pem` and `root-ca-key.pem`, respectively

- `endpoint`: _optional_. custom endpoint for using S3 compatible provider.

- `disable_ssl`: _optional_. disable SSL for the endpoint, useful for S3 compatible providers without SSL.

### behavior

#### `check`: check for intermediate ca

#### `in`: fetch intermediate ca certificate and private key

fetches the certificate and/or private key file for a root ca

the following files will be places in the destination, based on parameters:

- `/intermediate-ca.pem`: the intermediate ca certificate file

- `/intermediate-ca-key.pem`: the intermediate ca private key file

**parameters**

- `save_certificate`: _optional_. save the certificate file to disk. default: `true`

- `save_private_key`: _optional_. save the private key file to disk. default: `false`

#### `out`: create intermediate ca

creates a new intermediate ca certificate and private key and signs it using the root ca

note: parameters are mostly 1:1 analogous to their cfssl counterparts

see cfssl documentation for best practices and examples

**parameters**

- `CN`: _required_. the certificate common name

- `key`: _optional_. the key parameters

	- `algo`: _optional_. algorithm. default: `rsa`

	- `size`: _optional_. size. default: `2048`

- `ca`: _optional_. the ca parameters

	- `expiry`: _optional_. the expiration length to use for the ca (a time duration in the form understood by go's time package). default: `43800h`

- `names`: _optional_. array containing single dict with fields used when signing

	- `C`: _optional_. country code

	- `L`: _optional_. city / locality

	- `O`: _optional_. organization

	- `OU`: _optional_. organizational unit

	- `ST`: _optional_. state

## concourse-cfssl-leaf-resource

creates and gets leaf using cfssl

### source configuration

- `leaf_name`: _required_. the leaf name (used for file names, e.g.: `<leaf-name>.pem`)

- `bucket_name`: _required_. the name of the bucket.

- `access_key_id`: _required_. the aws access key id to use when accessing the bucket

- `secret_access_key`: _required_. the aws secret access key to use when accessing the bucket

- `region_name`: _required_. the region the bucket is in.

- `prefix`: _optional_. the prefix path to prepend to the cfssl files. e.g. `prefix: my/prefix/path` will result in a leaf cert file path of `<bucket>/my/prefix/path/<leaf-name>.pem` default: `null`  
  
  note: this path must also contain the intermediate ca certificate and private key under `intermediate-ca.pem` and `intermediate-ca-key.pem`, respectively

- `endpoint`: _optional_. custom endpoint for using S3 compatible provider.

- `disable_ssl`: _optional_. disable SSL for the endpoint, useful for S3 compatible providers without SSL.

### behavior

#### `check`: check for leaf

#### `in`: fetch leaf certificate, private key, and/or ca chain

fetches the certificate, private key, and/or ca chain for a leaf

the following files will be places in the destination, based on parameters:

- `/<leaf_name>.pem`: the leaf certificate file

- `/<leaf_name>-key.pem`: the leaf private key file

- `/ca-chain.pem`: the ca certificate chain file

**parameters**

- `save_certificate`: _optional_. save the certificate file to disk. default: `true`

- `save_private_key`: _optional_. save the private key file to disk. default: `false`

- `save_ca_chain`: _optional_. save the ca certificate chain file to disk. default: `false`

#### `out`: create leaf

creates a new leaf certificate and private key and signs it using the intermediate ca

note: parameters are mostly 1:1 analogous to their cfssl counterparts

see cfssl documentation for best practices and examples

**parameters**

- `CN`: _required_. the certificate common name

- `key`: _optional_. the key parameters

	- `algo`: _optional_. algorithm. default: `rsa`

	- `size`: _optional_. size. default: `2048`

- `leaf`: _optional_. the leaf parameters

	- `expiry`: _optional_. the expiration length to use for the leaf (a time duration in the form understood by go's time package). default: `8760h`

	- `usages`: _optional_. array of key usages.

		default:
		
		```
		["signing",
		 "key encipherment",
		 "server auth",
		 "client auth"]
       ```

	- `hosts`: _optional_. array of SANs. default: `null`

- `names`: _optional_. array containing single dict with fields used when signing

	- `C`: _optional_. country code

	- `L`: _optional_. city / locality

	- `O`: _optional_. organization

	- `OU`: _optional_. organizational unit

	- `ST`: _optional_. state

## development

install python 3.6 and requirements from `requirements-dev.txt`

install cfssl

`.vscode/settings.json` will enable linters in vscode

## building

builds are handled automatically by [docker hub](https://hub.docker.com)

the baseline image is built upon every commit to master

once that is built, the resource images are automatically triggered and built

## license

see [LICENSE](LICENSE)
