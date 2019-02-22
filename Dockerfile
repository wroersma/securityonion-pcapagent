FROM python:3.7-alpine AS securityonion-pcapagent


RUN mkdir /opt/securityonion-pcapagent/

ENV FLASK_APP=so_pcapagent.py

COPY requirements.txt /opt/securityonion-pcapagent

WORKDIR /opt/securityonion-pcapagent

RUN apk update
RUN apk upgrade

RUN apk add --no-cache \
    gcc \
    libc-dev \
    musl-dev \
    linux-headers \
    libffi-dev \
    python3-dev \
    g++ \
  && pip install --upgrade pip \
  && pip install -r /opt/securityonion-pcapagent/requirements.txt --upgrade \
  && apk del --purge gcc \
    libc-dev \
    musl-dev \
    linux-headers \
    libffi-dev \
    python3-dev \
    g++

COPY so_pcapagent.py /opt/securityonion-pcapagent
COPY app /opt/securityonion-pcapagent/app
COPY babel.cfg /opt/securityonion-pcapagent
COPY LICENSE /opt/securityonion-pcapagent
COPY config.py /opt/securityonion-pcapagent
COPY config.json /opt/securityonion-pcapagent

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0"]
