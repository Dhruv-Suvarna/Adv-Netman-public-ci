#!/usr/bin/env python3
"""Run inside an approved Ubuntu router via stdin; payload arrives through stdin."""
import hashlib, json, os, pathlib, subprocess, sys, time
payload = json.load(sys.stdin)
base = pathlib.Path('/etc/snmp')
def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)
if subprocess.run(['dpkg-query','-W','-f=${Status}','snmpd'],capture_output=True,text=True).stdout != 'install ok installed':
    # Container PID 1 is not systemd. Prevent package scripts starting a default agent.
    policy=pathlib.Path('/usr/sbin/policy-rc.d')
    original=policy.read_bytes() if policy.exists() else None
    mode=policy.stat().st_mode & 0o777 if policy.exists() else None
    try:
        policy.write_text('#!/bin/sh\nexit 101\n'); policy.chmod(0o755)
        run('apt-get','update')
        run('env','DEBIAN_FRONTEND=noninteractive','apt-get','install','-y','snmpd','snmp')
    finally:
        if original is None: policy.unlink()
        else: policy.write_bytes(original); policy.chmod(mode)
base.mkdir(exist_ok=True)
config=base/'nmas-snmpd.conf'
changed=not config.exists() or config.read_text()!=payload['config']
pidfile=pathlib.Path('/run/nmas-snmpd.pid')
running=False
if pidfile.exists():
    pid=pidfile.read_text().strip()
    proc=pathlib.Path('/proc')/pid/'cmdline'
    running=proc.exists() and b'nmas-snmpd.conf' in proc.read_bytes()
if changed and running:
    run('start-stop-daemon','--stop','--retry','TERM/10/KILL/5','--pidfile',str(pidfile),'--exec','/usr/sbin/snmpd')
    running=False
if changed:
    config.write_text(payload['config']); config.chmod(0o600)
state=pathlib.Path('/var/lib/snmp/snmpd.conf')
state.parent.mkdir(exist_ok=True)
# Net-SNMP consumes createUser and persists USM entries with the security
# name hex-encoded (e.g. "0x6e6d61732d..."), never as literal plain text.
user_hex='0x'+payload['username'].encode().hex()
if not state.exists() or user_hex not in state.read_text().lower():
    if running: raise SystemExit('Missing USM user in an active daemon; refuse unsafe live key replacement')
    with state.open('a') as f:
        f.write('\ncreateUser '+payload['username']+' SHA-256 '+payload['auth_password']+' AES '+payload['privacy_password']+'\n')
    state.chmod(0o600)
if not running:
    run('/usr/sbin/snmpd','-C','-c',str(config)+','+str(state),'-p',str(pidfile),'-Lf','/var/log/nmas-snmpd.log')
    time.sleep(1)
print('snmpd '+('converged' if changed else 'unchanged')+' pid='+pidfile.read_text().strip())

watcher=base/'nmas-link-events.py'
event_config=base/'nmas-link-events.json'
event_text=json.dumps(payload['events'],sort_keys=True)
event_changed=not watcher.exists() or watcher.read_text()!=payload['watcher'] or not event_config.exists() or event_config.read_text()!=event_text
event_pid=pathlib.Path('/run/nmas-link-events.pid')
# This container has no init/reaper (PID 1 is not systemd -- see AGENTS.md),
# so an exited watcher becomes a zombie whose /proc/<pid>/cmdline path still
# *exists* (as an empty file) until something reaps it, which here is never.
# A bare `.exists()` check on that path therefore misreports a dead watcher
# as running. Match the already-correct snmpd pattern above: require the
# cmdline to actually contain this watcher's own script path.
event_running=False
if event_pid.exists():
    event_cmdline=pathlib.Path('/proc')/event_pid.read_text().strip()/'cmdline'
    event_running=event_cmdline.exists() and str(watcher).encode() in event_cmdline.read_bytes()
if event_running and event_changed:
    run('start-stop-daemon','--stop','--retry','TERM/10/KILL/5','--pidfile',str(event_pid),'--exec','/usr/bin/python3')
    event_running=False
if event_changed:
    watcher.write_text(payload['watcher']); watcher.chmod(0o600)
    event_config.write_text(event_text); event_config.chmod(0o600)
if not event_running:
    # A stale pidfile left by a dead/zombie watcher still names a PID that
    # exists in /proc (see above), which makes start-stop-daemon's own
    # --pidfile liveness check refuse to start a replacement ("process
    # already running"). Since we have already independently determined the
    # watcher is not really running, it is safe to clear the stale pidfile
    # before asking start-stop-daemon to (re)create it.
    if event_pid.exists(): event_pid.unlink()
    run('start-stop-daemon','--start','--background','--make-pidfile','--pidfile',str(event_pid),'--startas','/usr/bin/python3','--',str(watcher))
    time.sleep(1)
print('link watcher '+('converged' if event_changed else 'unchanged')+' pid='+event_pid.read_text().strip())
