FROM snapkitchen/concourse-cfssl-baseline

COPY resources/intermediate_ca/scripts/check \
    resources/intermediate_ca/scripts/in \
    resources/intermediate_ca/scripts/out \
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
