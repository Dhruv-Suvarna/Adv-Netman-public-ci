#!/usr/bin/env python3
"""Deployed verbatim to /etc/snmp/nmas-trap-ingest.py and invoked synchronously
by snmptrapd's `traphandle default` directive, once per notification that has
already passed SNMPv3 USM authentication and authorization. snmptrapd blocks
while this runs, so every step is bounded by a short timeout and every error
path exits quickly without raising back into the daemon.

Never scrapes logs: the notification is fed on stdin by snmptrapd itself in
its documented traphandle format (hostname, transport address, then one
"OID value" line per varbind, sysUpTime.0 and snmpTrapOID.0 first).
"""
import json, pathlib, re, sys, time

ETC = pathlib.Path('/etc/snmp')
LOG = pathlib.Path('/var/log/nmas-trap-ingest.log')


def log(message):
    try:
        with LOG.open('a') as stream:
            stream.write(time.strftime('%Y-%m-%dT%H:%M:%S ') + message + '\n')
    except OSError:
        pass


def fail(message):
    log('FAIL ' + message)
    sys.exit(1)


def load(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        fail(f'cannot read {path}: {exc}')


def parse_varbind(line):
    # Same shape as the polling parser: "<oid> = [<kind>: ]<value>".
    match = re.match(r'\.?(?P<oid>\d+(?:\.\d+)*)\s*=\s*(?:(?P<kind>[\w-]+):\s*)?(?P<value>.*)$', line)
    if match:
        return match.group('oid'), match.group('value').strip()
    # Fallback: "<oid><space><value>" with no '=' or type prefix.
    parts = line.strip().lstrip('.').split(None, 1)
    if len(parts) == 2 and re.fullmatch(r'\d+(?:\.\d+)*', parts[0]):
        return parts[0], parts[1].strip()
    return None, None


def main():
    raw = sys.stdin.read()
    lines = raw.splitlines()
    if len(lines) < 2:
        fail('malformed traphandle input (fewer than 2 lines)')
    address = lines[1]
    ip_match = re.search(r'\[(?:UDP6?|TCP6?): ?\[?([0-9a-fA-F.:]+)\]?\]?:', address) or re.search(r'\[([0-9a-fA-F.:]+)\]', address)
    source_ip = ip_match.group(1) if ip_match else 'unknown'

    oids = load(ETC / 'nmas-trap-oids.json')
    devices = load(ETC / 'nmas-trap-devices.json')
    device = devices.get(source_ip, source_ip)

    varbinds = {}
    for line in lines[2:]:
        oid, value = parse_varbind(line)
        if oid:
            varbinds[oid] = value

    trap_oid = varbinds.get(oids['snmpTrapOID'].lstrip('.'))
    if not trap_oid:
        fail(f'no snmpTrapOID varbind found from {source_ip}; raw={lines!r}')
    trap_oid = trap_oid.lstrip('.')
    # OID values may arrive as "OID: .1.2.3" (kind-prefixed) or bare "1.2.3".
    trap_oid = trap_oid.split()[-1].lstrip('.')

    names = {v.lstrip('.'): k for k, v in oids.items() if k not in ('snmpTrapOID',) and isinstance(v, str)}
    event_type = names.get(trap_oid, 'other')
    severity = {'linkDown': 'warning', 'linkUp': 'info', 'coldStart': 'info',
                'ceosTestNotification': 'info', 'other': 'info'}.get(event_type, 'info')

    def column_value(prefix):
        prefix = oids[prefix].lstrip('.') + '.'
        for oid, value in varbinds.items():
            if oid.startswith(prefix):
                return oid[len(prefix):], value
        return None, None

    ifindex, _ = column_value('ifIndex') if 'ifIndex' in oids else (None, None)
    _, admin = column_value('ifAdminStatus') if 'ifAdminStatus' in oids else (None, None)
    _, oper = column_value('ifOperStatus') if 'ifOperStatus' in oids else (None, None)

    def tag(value):
        return str(value).replace('\\', '\\\\').replace(' ', '\\ ').replace(',', '\\,').replace('=', '\\=')

    def field_str(value):
        return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'

    tags = f'device={tag(device)},source_ip={tag(source_ip)},source_protocol=snmp,event_type={tag(event_type)},notification_oid={tag(trap_oid)},severity={tag(severity)}'
    if ifindex is not None:
        tags += f',ifindex={tag(ifindex)}'
    fields = ['value=1i']
    if admin is not None and admin.isdigit():
        fields.append('ifadminstatus=' + admin + 'i')
    if oper is not None and oper.isdigit():
        fields.append('ifoperstatus=' + oper + 'i')
    fields.append('raw_varbinds=' + field_str('; '.join(f'{o}={v}' for o, v in varbinds.items())))
    line_protocol = f'snmp_trap,{tags} {",".join(fields)} {time.time_ns()}'

    env = {}
    for envline in (ETC / 'nmas-trap-ingest.env').read_text().splitlines():
        if '=' in envline:
            key, _, value = envline.partition('=')
            env[key] = value
    missing = {'INFLUXDB_ORG', 'INFLUXDB_BUCKET', 'INFLUXDB_TOKEN'} - env.keys()
    if missing:
        fail('ingest credentials incomplete: missing ' + ','.join(sorted(missing)))

    import requests
    try:
        r = requests.post('http://127.0.0.1:8086/api/v2/write',
                           params={'org': env['INFLUXDB_ORG'], 'bucket': env['INFLUXDB_BUCKET'], 'precision': 'ns'},
                           headers={'Authorization': 'Token ' + env['INFLUXDB_TOKEN']},
                           data=line_protocol, timeout=5)
        r.raise_for_status()
    except Exception as exc:
        fail(f'InfluxDB write failed for {device}/{event_type}: {exc}')
    log(f'OK device={device} event_type={event_type} oid={trap_oid} source_ip={source_ip}')


if __name__ == '__main__':
    main()
