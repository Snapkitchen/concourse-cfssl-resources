ARG PARENT_IMAGE=snapkitchen/concourse-cfssl-baseline:latest
FROM $PARENT_IMAGE

COPY resources/intermediate-ca/scripts/check \
    resources/intermediate-ca/scripts/in \
    resources/intermediate-ca/scripts/out \
    /opt/resource/
COPY lib/__init__.py \
    lib/cfssl.py \
    lib/concourse.py \
    lib/log.py \
    /opt/resource/lib/

WORKDIR /opt/resource
