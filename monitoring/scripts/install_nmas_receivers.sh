#!/usr/bin/env bash
set -euo pipefail
BASE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONFIG_DIR="$BASE_DIR/config"

# Converge files without changing timestamps or restarting healthy services.
changed=0
install_config() {
    local source=$1 target=$2
    if ! sudo -n cmp -s "$source" "$target" || [[ $(sudo -n stat -c '%u:%g:%a' "$target" 2>/dev/null || true) != 0:0:644 ]]; then
        sudo -n install -m 0644 -o root -g root "$source" "$target"
        changed=1
    fi
}
bound_only() {
    [[ $(ss -H -ln"$1" | awk -v port="$2" '$4 ~ (":" port "$") {print $4}' | sort -u) == "192.168.200.100:$2" ]]
}

sudo -n install -d -o syslog -g adm -m 0750 /var/log/lab-monitoring
for file in remote-syslog.log snmptrapd.log; do
    path="/var/log/lab-monitoring/$file"
    if ! sudo -n test -e "$path"; then
        sudo -n install -o syslog -g adm -m 0640 /dev/null "$path"
    elif [[ $(sudo -n stat -c '%U:%G:%a' "$path") != syslog:adm:640 ]]; then
        sudo -n chown syslog:adm "$path"
        sudo -n chmod 0640 "$path"
    fi
done
install_config "$CONFIG_DIR/lab-monitoring-logrotate" /etc/logrotate.d/lab-monitoring
rotation_check=$(sudo -n logrotate -d /etc/logrotate.d/lab-monitoring 2>&1)
if grep -q '^error:' <<< "$rotation_check"; then
    printf '%s\n' "$rotation_check" >&2
    exit 1
fi
sudo -n systemctl enable --now logrotate.timer

changed=0
install_config "$CONFIG_DIR/rsyslog-lab-monitoring.conf" /etc/rsyslog.d/30-lab-monitoring.conf
sudo -n rsyslogd -N1
if ((changed)) || ! bound_only u 514 || ! bound_only t 514; then
    sudo -n systemctl restart rsyslog
fi
sudo -n systemctl enable --now rsyslog
sudo -n systemctl is-active --quiet rsyslog
printf '[ NMAS ] rsyslog ...................... PASS\n'

changed=0
install_config "$CONFIG_DIR/snmptrapd.conf" /etc/snmp/snmptrapd.conf
trap_changed=$changed
changed=0
sudo -n install -d /etc/systemd/system/snmptrapd.service.d /etc/systemd/system/snmptrapd.socket.d
install_config "$CONFIG_DIR/snmptrapd-service.conf" /etc/systemd/system/snmptrapd.service.d/nmas.conf
install_config "$CONFIG_DIR/snmptrapd-socket.conf" /etc/systemd/system/snmptrapd.socket.d/nmas.conf
if ((changed)); then
    sudo -n systemctl daemon-reload
fi
sudo -n systemd-analyze verify snmptrapd.service snmptrapd.socket
if ((changed || trap_changed)) || ! bound_only u 162; then
    sudo -n systemctl stop snmptrapd.service snmptrapd.socket
fi
sudo -n systemctl enable --now snmptrapd.socket
sudo -n systemctl enable --now snmptrapd.service
sudo -n systemctl is-active --quiet snmptrapd
printf '[ NMAS ] SNMP trap receiver ........... PASS\n'
