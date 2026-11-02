#!/usr/bin/env python3
"""Root-only receiver USM convergence from protected stdin, never argv secrets."""
import json, pathlib, subprocess, sys
payload=json.load(sys.stdin)
def run(*args): subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
config=pathlib.Path('/etc/snmp/snmptrapd.conf')
desired=('agentAddress udp:192.168.200.100:162\ndisableAuthorization no\nauthUser log,execute '+payload['username']+' priv\n'
         'format2 NMAS_SNMP source=%b version=%s varbinds=%v\\n\n'
         '# Runs only for notifications that already passed USM auth/authorization above;\n'
         '# ingests them into InfluxDB as discrete events. See docs/SNMP_IMPLEMENTATION.md.\n'
         'traphandle default /usr/bin/python3 /etc/snmp/nmas-trap-ingest.py\n')
state=pathlib.Path('/var/lib/snmp/snmptrapd.conf')
content=state.read_text() if state.exists() else ''
missing=[user for user in payload['users'] if '0x'+user['engine'].lower() not in content.lower()]
changed=not config.exists() or config.read_text()!=desired
if missing or changed:
    run('systemctl','stop','snmptrapd.service','snmptrapd.socket')
    if changed: config.write_text(desired); config.chmod(0o644)
    # Re-read after shutdown because Net-SNMP persists engine time and USM state.
    with state.open('a') as stream:
        for user in missing:
            stream.write('\ncreateUser -e 0x'+user['engine']+' '+payload['username']+' SHA-256 '+payload['auth_password']+' AES '+payload['privacy_password']+'\n')
    run('chown','Debian-snmp:Debian-snmp',str(state)); state.chmod(0o600)
    run('systemctl','start','snmptrapd.socket','snmptrapd.service')

# Trap ingestion: script + non-secret lookup tables are world-readable, root-owned;
# only the InfluxDB token lives in a Debian-snmp-only protected file. Writing these
# never requires a restart -- snmptrapd re-invokes the traphandle program fresh
# for every notification, so it always sees current content on disk.
etc=pathlib.Path('/etc/snmp')
ingest_changed=False
script_path=etc/'nmas-trap-ingest.py'
if not script_path.exists() or script_path.read_text()!=payload['trap_ingest_script']:
    script_path.write_text(payload['trap_ingest_script']); script_path.chmod(0o755)
    run('chown','root:root',str(script_path))
    ingest_changed=True
oids_path=etc/'nmas-trap-oids.json'
oids_text=json.dumps(payload['trap_oids'],sort_keys=True)
if not oids_path.exists() or oids_path.read_text()!=oids_text:
    oids_path.write_text(oids_text); oids_path.chmod(0o644)
    run('chown','root:root',str(oids_path))
    ingest_changed=True
devices_path=etc/'nmas-trap-devices.json'
devices_text=json.dumps(payload['device_map'],sort_keys=True)
if not devices_path.exists() or devices_path.read_text()!=devices_text:
    devices_path.write_text(devices_text); devices_path.chmod(0o644)
    run('chown','root:root',str(devices_path))
    ingest_changed=True
env_path=etc/'nmas-trap-ingest.env'
env_text='INFLUXDB_ORG='+payload['influx_org']+'\nINFLUXDB_BUCKET='+payload['influx_bucket']+'\nINFLUXDB_TOKEN='+payload['influx_token']+'\n'
env_changed=not env_path.exists() or env_path.read_text()!=env_text
if env_changed:
    env_path.write_text(env_text)
    run('chown','Debian-snmp:Debian-snmp',str(env_path)); env_path.chmod(0o600)
    ingest_changed=True
log_path=pathlib.Path('/var/log/nmas-trap-ingest.log')
if not log_path.exists():
    log_path.touch()
    run('chown','Debian-snmp:Debian-snmp',str(log_path)); log_path.chmod(0o640)

print('SNMP receiver '+('converged' if missing or changed else 'unchanged')+'; registered '+str(len(payload['users']))+' authoritative engines; trap ingestion '+('converged' if ingest_changed else 'unchanged'))
