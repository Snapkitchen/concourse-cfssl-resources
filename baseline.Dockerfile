FROM python:3.7.0-alpine3.8

RUN apk add --upgrade --no-cache \
      git~2.18 \
      go~1.10.1 \
      musl-dev~1.1.19 \
    && pip3 --no-cache-dir install --upgrade pip \
    && go get -u -v github.com/cloudflare/cfssl/cmd/cfssl \
    && go get -u -v github.com/cloudflare/cfssl/cmd/cfssljson

COPY requirements.txt /app/requirements.txt

RUN pip3 --no-cache-dir install -r /app/requirements.txt

ENTRYPOINT ["/bin/sh"]
