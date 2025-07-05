# phpIPAM Cron container

FROM alpine:3.20


RUN apk upgrade --no-cache \
    && apk add --no-cache tini tzdata iputils nmap fping composer git \
    && apk add --no-cache python3 py3-pip curl


RUN python3 -m pip config set global.break-system-packages true && \
    pip install --upgrade --no-cache-dir pip && \
    pip install --no-cache-dir requests pathlib 

RUN mkdir /phpipam
COPY ./customer_nmap.py /phpipam/customer_nmap.py
COPY ./crond/start_crond /start_crond
COPY ./crond/set_timezone /set_timezone
RUN chmod +x /start_crond /set_timezone

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="phpIPAM Cron Container" \
      org.label-schema.description="phpIPAM is an open-source web IP address management application (IPAM). Its goal is to provide light, modern and useful IP address management." \
      org.label-schema.url="https://phpipam.net/" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/phpipam/phpipam/" \
      org.label-schema.vendor="phpIPAM" \
      org.label-schema.version=$VERSION \
      org.label-schema.schema-version="1.0" \
      org.opencontainers.image.source="https://github.com/phpipam-docker/phpipam-docker" \
      maintainer="Gary Allan <github@gallan.co.uk>"

WORKDIR /phpipam

# Run busybox crond
ENTRYPOINT ["/sbin/tini", "--"]
CMD /start_crond
