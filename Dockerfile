# Build locally with:
#
#   docker build --build-arg JF_CONFIG="$(jf config export)" -t keyfactor/signserver .
#
# For instructions how to set up JFrog CLI (jf), see the documentation:
# https://docs-devops-int.k8s.primetest.se/development/work-with-artifactory.html#jfrog-cli

FROM keyfactor.jfrog.io/dev-oci/keyfactor-commons/wildfly/images/wildfly:alma9-jre11-wf26 as appserver
FROM almalinux:9 as builder

ARG JF_CONFIG

WORKDIR /build

# Install dependencies needed to build and package SignServer
RUN dnf install -y java-11-openjdk ant maven

# Install JFrog CLI to be able to pull JARs from keyfactor.jfrog.io
RUN echo "[jfrog]" > jfrog.repo && \
    echo "name = jfrog" >> jfrog.repo && \
    echo "baseurl = https://releases.jfrog.io/artifactory/jfrog-rpms" >> jfrog.repo && \
    echo "enabled = 1" >> jfrog.repo && \
    rpm --import https://releases.jfrog.io/artifactory/jfrog-gpg-public/jfrog_public_gpg.key && \
    mv jfrog.repo /etc/yum.repos.d && \
    dnf install -y jfrog-cli-v2-jf && \
    jf config import "$JF_CONFIG"

COPY . .
COPY --from=appserver /opt/keyfactor/appserver /opt/keyfactor/appserver

# Build and package SignServer
RUN cd signserver && \
    bin/ant init && \
    lib/maven-install-files.sh && \
    jf mvn install --no-transfer-progress \
        -DskipTests \
        -Dappserver.home=/opt/keyfactor/appserver \
        -Ddatabase.name=h2

FROM keyfactor.jfrog.io/dev-oci/keyfactor-commons/wildfly/images/wildfly:alma9-jre11-wf26

USER 0

# Disable container internal TLS setup by setting this to "false"
ENV TLS_SETUP_ENABLED true

# Database configuration that can be overridden
#  jdbc:h2:mem:ejbcadb;DB_CLOSE_DELAY=-1
#  jdbc:mysql://database:3306/signserver?characterEncoding=UTF-8
#  jdbc:postgresql://database/ejbca
# Default is H2 database persisted to disk on pod stop
ENV DATABASE_JDBC_URL jdbc:h2:/mnt/persistent/signserverdb;DB_CLOSE_DELAY=-1
ENV DATABASE_USER signserver
ENV DATABASE_PASSWORD signserver
# Table and index creation can run under a different database user, but schema upgrades will not work
#ENV DATABASE_USER_PRIVILEGED root
#ENV DATABASE_PASSWORD_PRIVILEGED password

ENV APPSRV_HOME /opt/keyfactor/appserver
ENV PATH "$PATH:/opt/keyfactor/bin:/opt/keyfactor/appserver/bin"

WORKDIR /opt/keyfactor

RUN mkdir /opt/keyfactor/signserver && \
    chown -R 10001:0 /opt/keyfactor/signserver

COPY --from=builder --chown=10001:0 /build/signserver/bin /opt/keyfactor/signserver/bin
COPY --from=builder --chown=10001:0 /build/signserver/lib /opt/keyfactor/signserver/lib
COPY --from=builder --chown=10001:0 /build/signserver/res /opt/keyfactor/signserver/res
COPY --from=builder --chown=10001:0 /build/signserver/mods-available /opt/keyfactor/signserver/mods-available
COPY --from=builder --chown=10001:0 /build/signserver/build.xml /opt/keyfactor/signserver/build.xml
COPY --chown=10001:0 container/conf /opt/keyfactor/signserver-custom/conf
COPY --chown=10001:0 container/opt/keyfactor/bin/internal /opt/keyfactor/bin/internal

# ant is needed to package the EAR on container start (see after-deployed-app-post-tls.sh)
# findutils is required by the SignServer CLI
RUN microdnf install --setopt=install_weak_deps=0 --assumeyes --nodocs ant findutils && \
    microdnf clean all && \
    rm -rf /var/cache/dnf /var/cache/yum

USER 10001

# Mount point where important data that should survive pod restarts can be stored
VOLUME /mnt/persistent

CMD ["/opt/keyfactor/bin/start.sh"]

