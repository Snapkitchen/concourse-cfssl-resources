FROM snapkitchen/concourse-cfssl-baseline

COPY resources/intermediate-ca/scripts/check \
    resources/intermediate-ca/scripts/in \
    resources/intermediate-ca/scripts/out \
    /opt/resource/
COPY lib/__init__.py \
    lib/aws.py \
    lib/cfssl.py \
    lib/concourse.py \
    lib/hash.py \
    lib/intermediate_ca.py \
    lib/log.py \
    lib/root_ca.py \
    /opt/resource/lib/

WORKDIR /opt/resource
