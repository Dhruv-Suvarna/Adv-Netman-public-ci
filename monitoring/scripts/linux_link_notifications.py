#!/usr/bin/env python3
"""Container-local link watcher; send real state transitions as SNMPv3 authPriv traps."""
import json, os, pathlib, subprocess, tempfile, time
root=pathlib.Path('/etc/snmp')
config=json.loads((root/'nmas-link-events.json').read_text())
state=pathlib.Path('/var/lib/snmp/nmas-events-boots')
boots=int(state.read_text())+1 if state.exists() else 1
state.write_text(str(boots)); state.chmod(0o600)
started=time.monotonic()
def links():
    result={}
    for path in pathlib.Path('/sys/class/net').iterdir():
        try:
            index=int((path/'ifindex').read_text())
            admin=1 if int((path/'flags').read_text(),16)&1 else 2
            oper=(path/'operstate').read_text().strip()
            # Linux dummy devices report unknown while administratively up.
            up=admin==1 and oper in ('up','unknown')
            result[index]=(admin,1 if up else 2)
        except FileNotFoundError: continue
    return result
with tempfile.TemporaryDirectory(prefix='nmas-event-') as directory:
    conf=pathlib.Path(directory)/'snmp.conf'
    conf.write_text('defVersion 3\ndefSecurityName '+config['username']+'\ndefSecurityLevel authPriv\ndefAuthType SHA-256\ndefAuthPassphrase '+config['auth_password']+'\ndefPrivType AES\ndefPrivPassphrase '+config['privacy_password']+'\nclientaddr '+config['address']+'\n')
    conf.chmod(0o600)
    env=dict(os.environ,SNMPCONFPATH=directory,MIBS='')
    previous=links()
    while True:
        time.sleep(2)
        current=links()
        for index,(admin,oper) in current.items():
            if index not in previous or previous[index][1]==oper: continue
            oid=config['linkUp'] if oper==1 else config['linkDown']
            args=['snmptrap','-e',config['notification_engine'],'-Z',str(boots)+','+str(int(time.monotonic()-started)),config['receiver']+':162','',oid]
            for key,value in (('ifIndex',index),('ifAdminStatus',admin),('ifOperStatus',oper)):
                args += [config[key]+'.'+str(index),'i',str(value)]
            result=subprocess.run(args,env=env,capture_output=True)
            if result.returncode: raise SystemExit('SNMPv3 link notification send failed')
        previous=current
