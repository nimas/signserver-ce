#!/usr/bin/env bash
# Installs WildFly as a systemd service on Ubuntu.
set -euo pipefail

VERSION="41.0.1.Final"
URL="https://github.com/wildfly/wildfly/releases/download/${VERSION}/wildfly-${VERSION}.tar.gz"
TMP="$(mktemp -d)"

echo "==> Installing Java 21"
sudo apt-get update
sudo apt-get install -y openjdk-21-jdk-headless

echo "==> Downloading WildFly ${VERSION}"
wget -q --show-progress -O "${TMP}/wildfly.tar.gz" "${URL}"

echo "==> Unpacking to /opt/wildfly-${VERSION}"
sudo tar -xzf "${TMP}/wildfly.tar.gz" -C /opt
sudo ln -sfn "/opt/wildfly-${VERSION}" /opt/wildfly

echo "==> Creating wildfly system user"
getent group wildfly >/dev/null || sudo groupadd -r wildfly
id wildfly >/dev/null 2>&1 || sudo useradd -r -g wildfly -d /opt/wildfly -s /sbin/nologin wildfly
sudo chown -RH wildfly:wildfly /opt/wildfly

echo "==> Installing systemd service"
SYSD=/opt/wildfly/docs/contrib/scripts/systemd
sudo mkdir -p /etc/wildfly
sudo cp "${SYSD}/wildfly.conf" /etc/wildfly/
sudo cp "${SYSD}/launch.sh" /opt/wildfly/bin/
sudo chmod +x /opt/wildfly/bin/*.sh
sudo cp "${SYSD}/wildfly.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wildfly

rm -rf "${TMP}"
sleep 5
systemctl --no-pager status wildfly | head -5
echo
echo "Done. WildFly: http://localhost:8080  Admin console: http://localhost:9990"
echo "Create an admin user with: sudo /opt/wildfly/bin/add-user.sh"
