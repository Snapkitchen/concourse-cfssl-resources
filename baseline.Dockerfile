FROM python:3.7.0-alpine3.8

RUN apk add --upgrade --no-cache \
      git~2.18 \
      go~1.10 \
      musl-dev~1.1 \
    && pip3 --no-cache-dir install --upgrade pip \
    && go get -u -v github.com/cloudflare/cfssl/cmd/cfssl \
    && go get -u -v github.com/cloudflare/cfssl/cmd/cfssljson

COPY requirements.txt /app/requirements.txt

RUN pip3 --no-cache-dir install -r /app/requirements.txt

# optionally install ptvsd
ARG PTVSD_INSTALL
RUN if [ -n "${PTVSD_INSTALL}" ]; then pip3 --no-cache-dir install ptvsd==4.2.0; fi
EXPOSE 5678/tcp

ENTRYPOINT ["/bin/sh"]
