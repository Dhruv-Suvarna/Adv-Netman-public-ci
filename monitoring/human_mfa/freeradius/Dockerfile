FROM debian:12.12-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ca-certificates freeradius freeradius-rest \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete

COPY dictionary /etc/freeradius/3.0/dictionary
COPY mods-available/privacyidea /etc/freeradius/3.0/mods-available/privacyidea
COPY sites-available/nmas-human-mfa /etc/freeradius/3.0/sites-available/nmas-human-mfa

RUN find /etc/freeradius/3.0/mods-enabled -mindepth 1 -delete \
    && ln -s ../mods-available/always /etc/freeradius/3.0/mods-enabled/always \
    && ln -s ../mods-available/expr /etc/freeradius/3.0/mods-enabled/expr \
    && ln -s ../mods-available/privacyidea /etc/freeradius/3.0/mods-enabled/privacyidea \
    && find /etc/freeradius/3.0/sites-enabled -mindepth 1 -delete \
    && ln -s ../sites-available/nmas-human-mfa /etc/freeradius/3.0/sites-enabled/nmas-human-mfa

EXPOSE 1812/udp
CMD ["freeradius", "-f"]
