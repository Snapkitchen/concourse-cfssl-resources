FROM snapkitchen/concourse-cfssl-baseline

COPY resources/root-ca/scripts/check \
    resources/root-ca/scripts/in \
    resources/root-ca/scripts/out \
    /opt/resource/
COPY lib/__init__.py \
    lib/aws.py \
    lib/cfssl.py \
    lib/concourse.py \
    lib/hash.py \
    lib/log.py \
    lib/root_ca.py \
    /opt/resource/lib/

WORKDIR /opt/resource
