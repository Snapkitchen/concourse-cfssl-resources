ARG PARENT_IMAGE=snapkitchen/concourse-cfssl-baseline:latest
FROM $PARENT_IMAGE

COPY resources/leaf/scripts/check \
    resources/leaf/scripts/in \
    resources/leaf/scripts/out \
    /opt/resource/
COPY lib/__init__.py \
    lib/cfssl.py \
    lib/concourse.py \
    lib/log.py \
    /opt/resource/lib/

WORKDIR /opt/resource
