#!/usr/bin/env bash
# Configures the local WildFly (/opt/wildfly) for a SignServer CE test deployment,
# following doc/htdocs/Application_Server_WildFly_32+_&_JBoss_EAP_8.html.
#
# Test setup only: file-based "nodb" database, SignServer's public demo TLS keys
# (res/test/dss10), and every listener bound to 127.0.0.1.
set -euo pipefail

WF=/opt/wildfly
SS="$(cd "$(dirname "$0")/signserver" && pwd)"
DEPLOY_USER="${SUDO_USER:-$USER}"
cli() { sudo -u wildfly "$WF/bin/jboss-cli.sh" --connect "$@"; }

wait_running() {
    for _ in $(seq 1 90); do
        if cli ':read-attribute(name=server-state)' 2>/dev/null | grep -q '"result" => "running"'; then
            return 0
        fi
        sleep 2
    done
    echo "WildFly did not reach the running state" >&2
    exit 1
}
reload() { cli ':reload' >/dev/null || true; sleep 3; wait_running; }

echo "==> Stopping WildFly for offline changes"
sudo systemctl stop wildfly

echo "==> Removing RESTEasy-Crypto (avoids Bouncy Castle conflicts)"
sudo sed -i '/.*org.jboss.resteasy.resteasy-crypto.*/d' "$WF/modules/system/layers/base/org/jboss/as/jaxrs/main/module.xml"
sudo rm -rf "$WF/modules/system/layers/base/org/jboss/resteasy/resteasy-crypto/"

echo "==> Writing standalone.conf (2 GB heap)"
TX_NODE_ID="$(od -A n -t d -N 1 /dev/urandom | tr -d ' ')"
sudo cp -n "$WF/bin/standalone.conf" "$WF/bin/standalone.conf.orig"
sudo tee "$WF/bin/standalone.conf" >/dev/null <<EOF
if [ "x\$JBOSS_MODULES_SYSTEM_PKGS" = "x" ]; then
     JBOSS_MODULES_SYSTEM_PKGS="org.jboss.byteman"
fi
if [ "x\$JAVA_OPTS" = "x" ]; then
     JAVA_OPTS="-Xms2048m -Xmx2048m -XX:MetaspaceSize=96M -XX:MaxMetaspaceSize=256m"
     JAVA_OPTS="\$JAVA_OPTS -Dhttps.protocols=TLSv1.2,TLSv1.3"
     JAVA_OPTS="\$JAVA_OPTS -Djdk.tls.client.protocols=TLSv1.2,TLSv1.3"
     JAVA_OPTS="\$JAVA_OPTS -Djava.net.preferIPv4Stack=true"
     JAVA_OPTS="\$JAVA_OPTS -Djboss.modules.system.pkgs=\$JBOSS_MODULES_SYSTEM_PKGS"
     JAVA_OPTS="\$JAVA_OPTS -Djava.awt.headless=true"
     JAVA_OPTS="\$JAVA_OPTS -Djboss.tx.node.id=${TX_NODE_ID}"
     JAVA_OPTS="\$JAVA_OPTS -XX:+HeapDumpOnOutOfMemoryError"
     JAVA_OPTS="\$JAVA_OPTS -Djdk.tls.ephemeralDHKeySize=2048"
else
     echo "JAVA_OPTS already set in environment; overriding default settings with values: \$JAVA_OPTS"
fi
EOF

echo "==> Binding WildFly to 127.0.0.1"
sudo sed -i 's/^WILDFLY_BIND=.*/WILDFLY_BIND=127.0.0.1/' /etc/wildfly/wildfly.conf

echo "==> Creating nodb directory and installing demo TLS keystores"
sudo install -d -o wildfly -g wildfly "$WF/standalone/data/nodb" "$WF/standalone/configuration/keystore"
sudo install -o wildfly -g wildfly -m 600 "$SS/res/test/dss10/dss10_demo-tls.jks" "$WF/standalone/configuration/keystore/keystore.jks"
sudo install -o wildfly -g wildfly -m 600 "$SS/res/test/dss10/dss10_truststore.jks" "$WF/standalone/configuration/keystore/truststore.jks"

echo "==> Creating credential store master password script"
if [ ! -f /usr/bin/wildfly_pass ]; then
    printf '#!/bin/sh\necho %s\n' "'$(openssl rand -base64 24)'" | sudo tee /usr/bin/wildfly_pass >/dev/null
fi
sudo chown wildfly:wildfly /usr/bin/wildfly_pass
sudo chmod 700 /usr/bin/wildfly_pass

echo "==> Letting ${DEPLOY_USER} write to the deployments folder (for bin/ant deploy)"
sudo apt-get install -y acl >/dev/null
sudo setfacl -m "u:${DEPLOY_USER}:rwx" "$WF/standalone/deployments"

echo "==> Starting WildFly"
sudo systemctl start wildfly
wait_running

echo "==> Credential store"
cli '/subsystem=elytron/credential-store=defaultCS:add(location=keystore/credentials, relative-to=jboss.server.config.dir, credential-reference={clear-text="{EXT}/usr/bin/wildfly_pass", type="COMMAND"}, create=true)'

echo "==> Remoting on port 4447 (for the SignServer Admin CLI)"
cli '/subsystem=remoting/http-connector=http-remoting-connector:write-attribute(name=connector-ref,value=remoting)'
cli '/socket-binding-group=standard-sockets/socket-binding=remoting:add(port=4447,interface=management)'
cli '/subsystem=undertow/server=default-server/http-listener=remoting:add(socket-binding=remoting,enable-http2=true)'
reload

echo "==> Logging"
for l in org.signserver org.cesecore org.ejbca com.keyfactor; do
    cli "/subsystem=logging/logger=$l:add(level=INFO)"
done

echo "==> Replacing default HTTP(S) listeners"
cli '/subsystem=undertow/server=default-server/http-listener=default:remove()'
cli '/subsystem=undertow/server=default-server/https-listener=https:remove()'
cli '/socket-binding-group=standard-sockets/socket-binding=http:remove()'
cli '/socket-binding-group=standard-sockets/socket-binding=https:remove()'
reload

echo "==> 3-port setup: 8080 HTTP, 8442 HTTPS, 8443 HTTPS + client certificate"
cli '/interface=http:add(inet-address="127.0.0.1")'
cli '/interface=httpspub:add(inet-address="127.0.0.1")'
cli '/interface=httpspriv:add(inet-address="127.0.0.1")'
cli '/socket-binding-group=standard-sockets/socket-binding=http:add(port="8080",interface="http")'
cli '/socket-binding-group=standard-sockets/socket-binding=httpspub:add(port="8442",interface="httpspub")'
cli '/socket-binding-group=standard-sockets/socket-binding=httpspriv:add(port="8443",interface="httpspriv")'

cli '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=httpsKeystorePassword, secret-value="serverpwd")'
cli '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=httpsTruststorePassword, secret-value="changeit")'
cli '/subsystem=elytron/key-store=httpsKS:add(path="keystore/keystore.jks",relative-to=jboss.server.config.dir,credential-reference={store=defaultCS, alias=httpsKeystorePassword},type=JKS)'
cli '/subsystem=elytron/key-store=httpsTS:add(path="keystore/truststore.jks",relative-to=jboss.server.config.dir,credential-reference={store=defaultCS, alias=httpsTruststorePassword},type=JKS)'
cli '/subsystem=elytron/key-manager=httpsKM:add(key-store=httpsKS,algorithm="SunX509",credential-reference={store=defaultCS, alias=httpsKeystorePassword})'
cli '/subsystem=elytron/trust-manager=httpsTM:add(key-store=httpsTS)'
cli '/subsystem=elytron/server-ssl-context=httpspub:add(key-manager=httpsKM,protocols=["TLSv1.3","TLSv1.2"],use-cipher-suites-order=false,cipher-suite-filter="TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",cipher-suite-names="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256")'
cli '/subsystem=elytron/server-ssl-context=httpspriv:add(key-manager=httpsKM,protocols=["TLSv1.3","TLSv1.2"],use-cipher-suites-order=false,cipher-suite-filter="TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",cipher-suite-names="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",trust-manager=httpsTM,need-client-auth=true)'

cli '/subsystem=undertow/server=default-server/http-listener=http:add(socket-binding="http", redirect-socket="httpspriv")'
cli '/subsystem=undertow/server=default-server/https-listener=httpspub:add(socket-binding="httpspub", ssl-context="httpspub", max-parameters=2048)'
cli '/subsystem=undertow/server=default-server/https-listener=httpspriv:add(socket-binding="httpspriv", ssl-context="httpspriv", max-parameters=2048)'
reload

echo
echo "WildFly is configured for SignServer."
