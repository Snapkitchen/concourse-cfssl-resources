FROM snapkitchen/concourse-cfssl-baseline

COPY resources/root-ca/scripts/ /opt/resource/
COPY lib/__init__.py /opt/resource/lib/
COPY lib/common.py /opt/resource/lib/
COPY lib/root_ca.py /opt/resource/lib/

WORKDIR /opt/resource
