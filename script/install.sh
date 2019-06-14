#!/usr/bin/env bash
cd /opt/
mkdir smith
cd smith/
curl -o /opt/smith/smithworker1 http://10.18.19.41/agent/release/agent
curl -o /etc/systemd/system/smith.service http://10.18.19.41/smith.service
chmod 755 /opt/smith/smithworker1
systemctl daemon-reload
systemctl restart smith.service
systemctl enable smith.service