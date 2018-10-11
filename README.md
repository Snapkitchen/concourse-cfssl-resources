# concourse-cfssl-resources

## table of contents

- [baseline](#concourse-cfssl-baseline)

- [root ca resource](#concourse-cfssl-root-ca-resource)
	- [source configuration](#source-configuration)
	- [behavior](#behavior)
		- [check](#check-check-for-root-ca)
		- [in](#in-fetch-root-ca-certificate-and-private-key)
		- [out](#out-create-or-renew-root-ca)
	- [examples](#examples)
		- [define resource](#define-resource)
		- [get keypair](#get-keypair)
		- [create keypair](#create-keypair)
		- [renew certificate](#renew-certificate)

- [intermediate ca resource](#concourse-cfssl-intermediate-ca-resource)
	- [source configuration](#source-configuration-1)
	- [behavior](#behavior-1)
		- [check](#check-check-for-intermediate-ca)
		- [in](#in-fetch-intermediate-ca-certificate-and-private-key)
		- [out](#out-create-intermediate-ca)
	- [examples](#examples-1)
		- [define resource](#define-resource-1)
		- [get keypair](#get-keypair-1)
		- [create keypair](#create-keypair-1)

- [leaf resource](#concourse-cfssl-leaf-resource)
	- [source configuration](#source-configuration-2)
	- [behavior](#behavior-2)
		- [check](#check-check-for-leaf)
		- [in](#in-fetch-leaf-certificate-private-key-and-parent-certificates)
		- [out](#out-create-leaf)
	- [examples](#examples-2)
		- [define resource](#define-resource-2)
		- [get keypair](#get-keypair-2)
		- [get keypair and parent certificates](#get-keypair-and-parent-certificates)
		- [create keypair](#create-keypair-2)

- [development](#development)

- [building](#building)

- [license](#license)

## concourse-cfssl-baseline

baseline for each concourse cfssl resource

includes:

- git (2.18.0)
- go (1.10.1)
- python3 (3.7)
- cfssl (latest)

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

#### `out`: create or renew root ca

creates a new root ca certificate and private key

note: parameters are mostly 1:1 analogous to their cfssl counterparts

see cfssl documentation for best practices and examples

**common parameters**

- `action`: _optional_. the operation to perform, either `create` or `renew`. default: `create`

**create parameters**

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

### examples

#### define resource

```
---
resource_types:
- name: cfssl-root-ca
  type: docker-image
  source:
    repository: snapkitchen/concourse-cfssl-root-ca-resource
    tag: latest

resources:
- name: my-root-ca
  type: cfssl-root-ca
  source:
    bucket_name: ((bucket_name))
    access_key_id: ((access_key_id))
    secret_access_key: ((secret_access_key))
    region_name: ((region_name))
    prefix: ((prefix))
```

#### get keypair

```
jobs:
- name: get-root-ca-keypair
  plan:
  - get: my-root-ca
    params:
      save_certificate: true
      save_private_key: true
```

#### create keypair

```
jobs:
- name: create-root-ca-keypair
  plan:
  - put: my-root-ca
    params:
      CN: RootCA
      names:
      - C: US
        L: Austin
        O: EXAMPLE
        OU: DevOps
        ST: Texas
```

#### renew certificate

```
jobs:
- name: renew-root-ca-certificate
  plan:
  - put: my-root-ca
    params:
      action: renew
```

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

### examples

#### define resource

```
---
resource_types:
- name: cfssl-intermediate-ca
  type: docker-image
  source:
    repository: snapkitchen/concourse-cfssl-intermediate-ca-resource
    tag: latest

resources:
- name: my-intermediate-ca
  type: cfssl-intermediate-ca
  source:
    bucket_name: ((bucket_name))
    access_key_id: ((access_key_id))
    secret_access_key: ((secret_access_key))
    region_name: ((region_name))
    prefix: ((prefix))
```

#### get keypair

```
jobs:
- name: get-intermediate-ca-keypair
  plan:
  - get: my-intermediate-ca
    params:
      save_certificate: true
      save_private_key: true
```

#### create keypair

```
jobs:
- name: create-intermediate-ca-keypair
  plan:
  - put: my-intermediate-ca
    params:
      CN: IntermediateCA
      names:
      - C: US
        L: Austin
        O: EXAMPLE
        OU: DevOps
        ST: Texas
```

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

#### `in`: fetch leaf certificate, private key, and parent certificates

fetches the leaf certificate, leaf private key, root ca certificate, and intermediate ca certificate

the following files will be places in the destination, based on parameters:

- `/<leaf_name>.pem`: the leaf certificate file

- `/<leaf_name>-key.pem`: the leaf private key file

- `/root-ca.pem`: the root ca certificate file

- `/intermediate-ca.pem`: the intermediate ca certificate file

**parameters**

- `save_certificate`: _optional_. save the certificate file to disk. default: `true`

- `save_private_key`: _optional_. save the private key file to disk. default: `false`

- `save_root_ca_certificate`: _optional_. save the root ca certificate file to disk. default: `false`

- `save_intermediate_ca_certificate`: _optional_. save the intermediate ca certificate file to disk. default: `false`

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

### examples

#### define resource

```
---
resource_types:
- name: cfssl-leaf
  type: docker-image
  source:
    repository: snapkitchen/concourse-cfssl-leaf-resource
    tag: latest

resources:
- name: server-leaf
  type: cfssl-leaf
  source:
    leaf_name: server
    bucket_name: ((bucket_name))
    access_key_id: ((access_key_id))
    secret_access_key: ((secret_access_key))
    region_name: ((region_name))
    prefix: ((prefix))
```

#### get keypair

```
jobs:
- name: get-server-leaf-keypair
  plan:
  - get: server-leaf
    params:
      save_certificate: true
      save_private_key: true
```

#### get keypair and parent certificates

```
jobs:
- name: get-server-leaf-keypair-and-parents
  plan:
  - get: server-leaf
    params:
      save_certificate: true
      save_private_key: true
      save_root_ca_certificate: true
      save_intermediate_ca_certificate: true
```

#### create keypair

```
jobs:
- name: create-server-leaf-keypair
  plan:
  - put: server-leaf
    params:
      CN: server
      leaf:
        expiry: 26280h
        hosts:
        - server.node.local.consul
        - localhost
        - 127.0.0.1
        usages:
        - signing
        - key encipherment
        - server auth
      names:
      - C: US
        L: Austin
        O: EXAMPLE
        OU: DevOps
        ST: Texas
```

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
