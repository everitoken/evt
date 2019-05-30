FROM postgres:11.3

LABEL author="Harry <harrywong@live.com>" maintainer="Harry <harrywong@live.com>" version="1.2.0" \
  description="This is customized PostgreSQL image with pg_pathman support"

ARG POSTGRES_DEV_VERSION=11
ARG PATHMAN_VERSION=1.5.3

RUN set -x \
	&& apt-get update && apt-get install -y --no-install-recommends ca-certificates wget unzip make postgresql-server-dev-${POSTGRES_DEV_VERSION} gcc libc6-dev libssl-dev libkrb5-dev \
    && wget -O /tmp/pg_pathman.zip https://github.com/postgrespro/pg_pathman/archive/$PATHMAN_VERSION.zip \
	&& unzip /tmp/pg_pathman.zip  -d /tmp \
    && cd /tmp/pg_pathman-${PATHMAN_VERSION} \
    && make USE_PGXS=1 install \
    && rm -rf /var/lib/apt/lists/* && apt-get purge -y --auto-remove ca-certificates wget unzip make postgresql-server-dev-${POSTGRES_DEV_VERSION} gcc libc6-dev libssl-dev libkrb5-dev \
    && rm -rf /tmp/pg_*

ENV POSTGRES_USERNAME="postgres"
ENV POSTGRES_INITDB_ARGS="-D /var/lib/postgresql/data"
ENV POSTGRES_DATA="/var/lib/postgresql/data"
# PGDATA is used for locating postgresql.conf file and
# real data folder is configured in it
ENV PGDATA="/var/lib/postgresql/config"
ENV AUTH="trust"

RUN mkdir -p $PGDATA
RUN cp /usr/share/postgresql/postgresql.conf.sample $PGDATA/postgresql.conf
RUN sed -i -e "s/#include_dir = ''/include_dir = 'conf.d'/" $PGDATA/postgresql.conf
COPY conf.d $PGDATA/conf.d/

RUN mkdir -p /docker-entrypoint-initdb.d
COPY initdb.d /docker-entrypoint-initdb.d/

COPY docker-entrypoint.sh /usr/local/bin/

VOLUME /var/lib/postgresql/data
