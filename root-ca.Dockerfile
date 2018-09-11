FROM snapkitchen/concourse-cfssl-baseline

COPY lib/lib.py /opt/resource/
COPY resources/root-ca/scripts/ /opt/resource/
