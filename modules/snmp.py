"""SNMP IaC and one-shot polling for the deployed inventory; no Lab 1 changes."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time

import requests
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from modules.nmas import BASE, MONITORING, NmasError, verify_nmas
from modules.cpu_alerts import evaluate_cpu_threshold, confirm_stored as cpu_alert_confirm_stored
from modules.monitoring_config import load_snmp_oids

RUNTIME = MONITORING / 'runtime'
OIDS = load_snmp_oids()   # validated: a malformed snmp_oids.yml fails here, not mid-poll


def protected_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)
    path.chmod(0o600)


def credentials(create=False):
    path = RUNTIME / 'snmp-secrets.json'
    if not path.exists() and create:
        protected_json(path, {'auth_password': secrets.token_hex(24), 'privacy_password': secrets.token_hex(24)})
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
        raise NmasError('SNMP credentials missing or insecure; require protected snmp-secrets.json')
    value = json.loads(path.read_text())
    if any(not re.fullmatch('[a-zA-Z0-9]{16,128}', value.get(k,'')) for k in ('auth_password','privacy_password')):
        raise NmasError('Invalid SNMP runtime credentials')
    return value


def command(args, data=None, timeout=120):
    result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        message=result.stderr + result.stdout
        path=RUNTIME/'snmp-secrets.json'
        if path.exists():
            for value in json.loads(path.read_text()).values(): message=message.replace(value,'[REDACTED]')
        raise NmasError(f'SNMP command failed ({args[0]}): {message[-1500:]}')
    return result.stdout


def docker(*args, data=None, timeout=120):
    prefix=['docker']
    if subprocess.run(['docker','info'],capture_output=True).returncode:
        prefix=['sudo','-n','docker']
    return command([*prefix,*args],data,timeout)


def devices():
    inventory=yaml.safe_load((BASE/'inventory.yml').read_text())
    policy=inventory['snmp']
    if policy['auth']!='SHA-256' or policy['privacy']!='AES':
        raise NmasError('Only verified SHA-256/AES authPriv profile is supported')
    result=[]
    for name,meta in inventory['network_devices'].items():
        if 'monitoring' not in meta: raise NmasError(f'{name}: monitoring metadata missing')
        item=dict(meta['monitoring'], device=name, container='clab-'+inventory['lab_name']+'-'+name, **policy)
        info=json.loads(docker('inspect',item['container']))[0]
        if not info['State']['Running']: raise NmasError(f'{name}: container is not running')
        if item['address']=='auto':
            item['address']=next(n['IPAddress'] for n in info['NetworkSettings']['Networks'].values() if n.get('IPAddress','').startswith('172.20.20.'))
        if item['platform'] not in ('ceos','linux'): raise NmasError(f'{name}: unsupported platform')
        result.append(item)
    return result


def render(name, context):
    return Environment(loader=FileSystemLoader(BASE/'templates/monitoring'),undefined=StrictUndefined).get_template(name).render(**context)+'\n'


def cli(item, text):
    result=docker('exec','-i',item['container'],'Cli','-p','15','--abort-on-error',data=text+'\n')
    if re.search(r'% (Invalid|Error|Incomplete|Unrecognized|Ambiguous)',result):
        for value in credentials().values(): result=result.replace(value,'[REDACTED]')
        raise NmasError(item['device']+': EOS rejected SNMP configuration: '+result[-1000:])
    return result


def poll(item, oid, walk=False, security='authPriv'):
    keys=credentials()
    with tempfile.TemporaryDirectory(prefix='nmas-snmp-') as directory:
        path=Path(directory)/'snmp.conf'
        path.write_text(f'defVersion 3\ndefSecurityName {item["username"]}\ndefSecurityLevel {security}\ndefAuthType SHA-256\ndefAuthPassphrase {keys["auth_password"]}\ndefPrivType AES\ndefPrivPassphrase {keys["privacy_password"]}\nclientaddr {item["receiver"]}\n')
        path.chmod(0o600)
        env=dict(os.environ,SNMPCONFPATH=directory,MIBS='')
        result=subprocess.run(['snmpwalk' if walk else 'snmpget','-On','-Oe','-Ot','-t','2','-r','1',item['address'],oid],env=env,capture_output=True,text=True,timeout=60)
        if result.returncode: raise NmasError(item['device']+': SNMP '+security+' request failed: '+result.stderr.strip())
        values={}
        for line in result.stdout.splitlines():
            if 'No Such' in line or 'No more variables' in line: continue
            match=re.match(r'\.(\d+(?:\.\d+)*) = (?:(?P<kind>[\w-]+): )?(?P<value>.*)',line)
            if match:
                key,kind,value=match.groups()
                if kind in ('INTEGER','Gauge32','Counter32','Counter64','Timeticks') or (kind is None and value.isdigit()): value=int(value)
                else: value=value.strip('"')
                values[key]=value
        if not values: raise NmasError(item['device']+': requested OID has no usable values: '+oid)
        return values


def configure_device(item):
    context=dict(item,**credentials())
    if item['platform']=='linux':
        context['config']=render('snmpd.conf.j2',context)
        context['watcher']=(MONITORING/'scripts/linux_link_notifications.py').read_text()
        context['events']={**context, **{key:OIDS[key] for key in ('ifIndex','ifAdminStatus','ifOperStatus','linkDown','linkUp')}}
        context['events'].pop('watcher',None)
        context['events'].pop('config',None)
        context['events']['notification_engine']='0x80001f8804'+('nmas-'+item['device']+'-events').encode().hex()
        script=(MONITORING/'scripts/provision_linux_snmp.py').read_text()
        print(item['device']+': '+docker('exec','-i',item['container'],'python3','-c',script,data=json.dumps(context),timeout=600).strip(),flush=True)
    else:
        desired=render('ceos_snmp.j2',context)
        desired_hash=hashlib.sha256(desired.encode()).hexdigest()
        statefile=RUNTIME/(item['device']+'-snmp-state.json')
        current=cli(item,'show running-config | section snmp\nshow running-config | section NMAS_SNMP')
        current_hash=hashlib.sha256(current.encode()).hexdigest()
        prior=json.loads(statefile.read_text()) if statefile.exists() else {}
        if prior.get('desired')==desired_hash and prior.get('actual')==current_hash:
            poll(item,OIDS['sysName'])
            print(item['device']+': SNMP unchanged',flush=True)
            return
        cli(item,'configure terminal\n'+desired+'end')
        # Startup config holds localized/encrypted device keys, never copied to Git.
        cli(item,'write memory')
        current=cli(item,'show running-config | section snmp\nshow running-config | section NMAS_SNMP')
        protected_json(statefile,{'desired':desired_hash,'actual':hashlib.sha256(current.encode()).hexdigest()})
        print(item['device']+': SNMP converged',flush=True)


def ensure_receiver(items):
    users=[]
    for item in items:
        if item['platform']=='ceos':
            text=cli(item,'show snmp engineID')
            engine=re.search(r'Local SNMP EngineID:\s*([0-9a-fA-F]+)',text).group(1)
        else:
            values=poll(item,OIDS['engineID'])
            engine=next(iter(values.values())).replace(' ','').lower()
        users.append({'device':item['device'],'engine':engine})
        if item['platform']=='linux':
            users.append({'device':item['device']+'-events','engine':'80001f8804'+('nmas-'+item['device']+'-events').encode().hex()})
    _,env=influx()
    trap_oids={key:OIDS[key] for key in ('linkUp','linkDown','coldStart','ceosTestNotification','snmpTrapOID','ifIndex','ifAdminStatus','ifOperStatus')}
    payload={'users':users,'username':items[0]['username'],**credentials(),
             'device_map':{item['address']:item['device'] for item in items},
             'trap_ingest_script':(MONITORING/'scripts/ingest_snmp_trap.py').read_text(),
             'trap_oids':trap_oids,
             'influx_org':env['INFLUXDB_ORG'],'influx_bucket':env['INFLUXDB_BUCKET'],'influx_token':env['INFLUXDB_TOKEN']}
    command(['bash',str(MONITORING/'scripts/install_nmas_receivers.sh')])
    script=(MONITORING/'scripts/provision_snmp_receiver.py').read_text()
    print(command(['sudo','-n','python3','-c',script],json.dumps(payload)).strip(),flush=True)
    protected_json(RUNTIME/'snmp-engines.json',users)


def influx():
    env=dict(line.split('=',1) for line in (RUNTIME/'monitoring.env').read_text().splitlines() if '=' in line)
    session=requests.Session(); session.trust_env=False
    session.headers['Authorization']='Token '+env['INFLUXDB_TOKEN']
    return session,env


def tag(value):
    return str(value).replace('\\','\\\\').replace(' ','\\ ').replace(',','\\,').replace('=','\\=')


def collect(item):
    data={}
    for key in ('sysName','sysUpTime','ifIndex','ifDescr','ifName','ifAdminStatus','ifOperStatus'):
        data[key]=poll(item,OIDS[key],walk=key.startswith('if'))
    data['cpu']=poll(item,OIDS['cpu'][item['platform']],walk=True)
    hostname=next(iter(data['sysName'].values()))
    if hostname!=item['device']: raise NmasError(item['device']+': sysName does not match inventory')
    if not all(isinstance(v,int) and 0<=v<=100 for v in data['cpu'].values()): raise NmasError(item['device']+': invalid CPU values')
    if not all(v in (1,2,3) for v in data['ifAdminStatus'].values()): raise NmasError('Invalid interface admin state')
    if not all(isinstance(v,int) and 1<=v<=7 for v in data['ifOperStatus'].values()): raise NmasError('Invalid interface operational state')
    indices={oid.split('.')[-1] for oid in data['ifIndex']}
    for key in ('ifName','ifAdminStatus','ifOperStatus'):
        if {oid.split('.')[-1] for oid in data[key]} != indices: raise NmasError(item['device']+': incomplete interface table')
    tags=f'device={tag(item["device"])},hostname={tag(hostname)},management_ip={item["address"]},platform={item["platform"]},source_protocol=snmp'
    stamp=time.time_ns(); lines=[]
    for metric,values in data.items():
        if metric in ('ifName','ifDescr','sysName','ifIndex'): continue
        for oid,value in values.items():
            suffix=''
            if metric.startswith('if'):
                index=oid.split('.')[-1]; name=data['ifName'].get(OIDS['ifName']+'.'+index,index)
                suffix=f',ifindex={index},interface={tag(name)}'
            elif metric=='cpu': suffix=',cpu_index='+oid.split('.')[-1]
            lines.append(f'snmp_poll,{tags},metric={metric}{suffix} value={value}i {stamp}')
    session,env=influx()
    r=session.post('http://127.0.0.1:8086/api/v2/write',params={'org':env['INFLUXDB_ORG'],'bucket':env['INFLUXDB_BUCKET'],'precision':'ns'},data='\n'.join(lines),timeout=15); r.raise_for_status()
    query=f'from(bucket: {json.dumps(env["INFLUXDB_BUCKET"])}) |> range(start: time(v: {stamp}), stop: time(v: {stamp+1})) |> filter(fn: (r) => r._measurement == "snmp_poll" and r.device == "{item["device"]}")'
    r=session.post('http://127.0.0.1:8086/api/v2/query',params={'org':env['INFLUXDB_ORG']},headers={'Content-Type':'application/vnd.flux'},data=query,timeout=15); r.raise_for_status()
    if item['device'] not in r.text or ',cpu,' not in r.text and 'cpu' not in r.text: raise NmasError('InfluxDB query did not return the new CPU sample')
    # Collector-generated CPU threshold alerting (LAB_REQUIREMENTS.md section 4
    # "Notifications" path 2 / section 14 item 5): reuse this SAME real,
    # already-validated CPU poll -- never a second poll, never a synthetic
    # value. The mean is taken across every polled hrProcessorLoad index,
    # matching how the existing Grafana "Latest polled CPU"/"Polled CPU
    # utilization" panels already aggregate this metric. See
    # modules/cpu_alerts.py for the consecutive-sample/hysteresis policy and
    # docs/SNMP_IMPLEMENTATION.md for the full design.
    cpu_mean=sum(data['cpu'].values())/len(data['cpu']) if data['cpu'] else None   # no CPU rows: no sample (classified invalid, never normal)
    cpu_threshold_event=evaluate_cpu_threshold(item['device'],item['platform'],cpu_mean,timestamp_ns=stamp)
    return {'device':item['device'],'platform':item['platform'],'oids':data,'records_written':len(lines),'timestamp_ns':stamp,'query_rows':r.text.count('\n'),'cpu_mean':cpu_mean,'cpu_threshold_event':cpu_threshold_event}


def verify_snmp(items=None):
    items=items or devices(); results=[]; failed=[]
    print('DEVICE     AGENT AUTH SYSNAME UPTIME CPU IFSTATUS STORAGE')
    for item in items:
        try:
            result=collect(item)
            try:
                poll(item,OIDS['sysName'],security='noAuthNoPriv')
            except NmasError: pass
            else: raise NmasError('Unauthenticated read unexpectedly succeeded')
            results.append(result)
            print(f'{item["device"]:<10} PASS  PASS PASS    PASS   PASS PASS     PASS',flush=True)
        except Exception as exc:
            failed.append(item['device']); print(item['device']+': FAIL '+str(exc),flush=True)
    protected_json(RUNTIME/'snmp-verification.json',results)
    if failed: raise NmasError('SNMP verification failed: '+', '.join(failed))
    return results


def verify_trap_ingestion(items):
    required_modes={'/etc/snmp/nmas-trap-ingest.py':0o755,'/etc/snmp/nmas-trap-oids.json':0o644,'/etc/snmp/nmas-trap-devices.json':0o644}
    for path,mode in required_modes.items():
        info=Path(path)
        if not info.is_file(): raise NmasError('Trap ingestion file missing: '+path)
        if info.stat().st_mode&0o777!=mode: raise NmasError('Trap ingestion file has unexpected permissions: '+path)
    env_path=Path('/etc/snmp/nmas-trap-ingest.env')
    if not env_path.is_file() or env_path.stat().st_mode&0o777!=0o600:
        raise NmasError('Trap ingestion credentials file missing or insecure')
    trapd_conf=Path('/etc/snmp/snmptrapd.conf').read_text()
    if 'traphandle default /usr/bin/python3 /etc/snmp/nmas-trap-ingest.py' not in trapd_conf:
        raise NmasError('Receiver is missing the trap ingestion traphandle directive')
    target=next((item for item in items if item['platform']=='ceos'),None)
    if target is None:
        print('Trap ingestion: structural checks PASS (no cEOS device available for a live test)',flush=True)
        return
    cli(target,'test snmp notification')
    time.sleep(3)
    session,env=influx()
    query=(f'from(bucket: {json.dumps(env["INFLUXDB_BUCKET"])}) |> range(start: -2m) '
           '|> filter(fn: (r) => r._measurement == "snmp_trap" and r.device == "'+target['device']+'" '
           'and r.event_type == "ceosTestNotification")')
    r=session.post('http://127.0.0.1:8086/api/v2/query',params={'org':env['INFLUXDB_ORG']},headers={'Content-Type':'application/vnd.flux'},data=query,timeout=15)
    r.raise_for_status()
    if target['device'] not in r.text:
        raise NmasError('Trap ingestion verification: no fresh snmp_trap event stored for '+target['device'])
    print('Trap ingestion: PASS (verified via '+target['device']+' test notification -> InfluxDB)',flush=True)


def verify_cpu_threshold_alerting(items):
    """Safely and deterministically demonstrate the collector-generated CPU
    threshold alert/recovery path, without stressing any device, faking any
    CPU reading, or touching production alert-state.

    Method (see docs/SNMP_IMPLEMENTATION.md "Collector-generated CPU
    threshold alerting" for the full writeup):
      1. Poll ONE real device's CPU through the normal, already-verified SNMP
         path (the same `poll()` function `collect()` uses) -- this is a real
         measurement, not a fabricated one.
      2. Exercise the SAME production `evaluate_cpu_threshold()` function
         with a temporary, explicitly-labelled `verification=True` policy
         whose warning threshold is set just below that one real observed
         value, so the alert path triggers deterministically without ever
         needing to load a device's CPU. `consecutive_samples=1` in this
         verification-only policy so a single real sample is sufficient
         (the production policy's own consecutive-sample requirement is
         proven separately by the unit tests in
         monitoring/tests/test_cpu_alerts.py, which do not touch live
         devices or InfluxDB).
      3. Confirm the resulting event is actually stored in InfluxDB.
      4. Re-exercise the same evaluator with the verification threshold
         raised back above the same real observed value, so the identical
         evaluator function demonstrates the RECOVERY transition and resets
         the (verification-only) state back to normal.
    The verification-only policy and state file are entirely separate from
    the production policy/state for this device -- this never weakens, and
    is never confused with, normal alerting for any device.
    """
    item=items[0]
    real_cpu_values=poll(item,OIDS['cpu'][item['platform']],walk=True)
    real_cpu=sum(real_cpu_values.values())/len(real_cpu_values)
    trigger_policy={'warning_pct':max(0.0,real_cpu-1.0),'critical_pct':100.0,'consecutive_samples':1,'recovery_pct':max(0.0,real_cpu-2.0)}
    alert_stamp=time.time_ns()
    alert_event=evaluate_cpu_threshold(item['device'],item['platform'],real_cpu,policy=trigger_policy,verification=True,timestamp_ns=alert_stamp)
    if not alert_event or alert_event['transition']!='alert':
        raise NmasError('CPU threshold verification: expected a deterministic ALERT event from a real CPU sample, none was stored')
    if not cpu_alert_confirm_stored(alert_event):
        raise NmasError('CPU threshold verification: ALERT event not found in InfluxDB')
    recovery_policy={'warning_pct':min(99.0,real_cpu+10.0),'critical_pct':min(100.0,real_cpu+20.0),'consecutive_samples':1,'recovery_pct':min(98.0,real_cpu+5.0)}
    recovery_stamp=time.time_ns()
    recovery_event=evaluate_cpu_threshold(item['device'],item['platform'],real_cpu,policy=recovery_policy,verification=True,timestamp_ns=recovery_stamp)
    if not recovery_event or recovery_event['transition']!='recovery':
        raise NmasError('CPU threshold verification: expected a deterministic RECOVERY event, none was stored')
    if not cpu_alert_confirm_stored(recovery_event):
        raise NmasError('CPU threshold verification: RECOVERY event not found in InfluxDB')
    print(f'CPU threshold alerting: PASS (device={item["device"]} real_cpu={real_cpu:.1f}% via normal SNMP poll; '
          f'collector ALERT+RECOVERY stored in InfluxDB using a verification-only threshold, not a device trap)',flush=True)
    return {'device':item['device'],'real_cpu':real_cpu,'alert_event':alert_event,'recovery_event':recovery_event}


def ensure_snmp_infrastructure(verbose=False):
    verify_nmas(verbose)
    items=devices()
    credentials(create=True)
    for item in items: configure_device(item)
    ensure_receiver(items)
    verify_snmp(items)
    verify_trap_ingestion(items)
    verify_cpu_threshold_alerting(items)
    verify_nmas(verbose)
