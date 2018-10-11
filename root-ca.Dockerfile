FROM snapkitchen/concourse-cfssl-baseline:latest

COPY resources/root-ca/scripts/check \
    resources/root-ca/scripts/in \
    resources/root-ca/scripts/out \
    /opt/resource/
COPY lib/__init__.py \
    lib/cfssl.py \
    lib/concourse.py \
    lib/log.py \
    /opt/resource/lib/

WORKDIR /opt/resource
