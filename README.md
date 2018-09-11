# concourse-cfssl-resources

## concourse-cfssl-baseline

baseline for each concourse cfssl resource

includes:

- bash (4.4.19)
- git (2.18.0)
- go (1.10.1)
- python3 (3.6.6)
- cfssl

## concourse-cfssl-root-ca-resource

TODO

## concourse-cfssl-intermediate-ca-resource

TODO

## concourse-cfssl-server-cert-resource

TODO

## concourse-cfssl-client-cert-resource

TODO

## building

builds are handled automatically by [docker hub](https://hub.docker.com)

the baseline image is built upon every commit to master

once that is built, the resource images are automatically triggered and built
