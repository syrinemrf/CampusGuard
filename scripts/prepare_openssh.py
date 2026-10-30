"""Reproducible sanitized Loghub OpenSSH sample. Dates replayed, not original year."""
import argparse
import hashlib
import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SOURCE = 'https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log'
PATTERN = re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[\d+\]:\s+(.*)$')
IP = re.compile(r'(?<!\w)(?:\d{1,3}\.){3}\d{1,3}(?!\w)')
USER = re.compile(r'(?:invalid user |for (?:invalid user )?)([\w.-]+)', re.I)

def sanitize(text):
    """Pseudonymize IPs and SSH usernames consistently, without leaking originals."""
    text = IP.sub(lambda m: 'ip_' + hashlib.sha256(('campusguard-demo:'+m.group()).encode()).hexdigest()[:10], text)
    text = USER.sub(lambda m: m.group(0)[:m.start(1)-m.start(0)] + 'user_' + hashlib.sha256(('campusguard-demo:'+m.group(1)).encode()).hexdigest()[:10], text)
    return text

def prepare(src, dest, limit):
    dest.parent.mkdir(parents=True, exist_ok=True)
    count=parsed=0
    with src.open(encoding='utf-8', errors='replace') as inp, dest.open('w',encoding='utf-8') as out:
        for line in inp:
            if count >= limit: break
            count += 1
            m=PATTERN.match(line.strip())
            if not m: continue
            parsed += 1
            stamp, host, message=m.groups()
            failure=bool(re.search(r'Failed password|Invalid user|authentication failure', message, re.I))
            success=bool(re.search(r'Accepted password|Accepted publickey', message, re.I))
            event={'@timestamp':datetime.strptime('2026 '+stamp,'%Y %b %d %H:%M:%S').replace(tzinfo=timezone.utc).isoformat(),
                   'service':{'name':'openssh'},'log':{'level':'WARNING' if failure else 'INFO'},
                   'event':{'category':'authentication','action':'ssh-login' if failure or success else 'ssh-other','outcome':'failure' if failure else ('success' if success else 'unknown')},
                   'message':sanitize(message),'labels':{'provenance':'loghub-openssh','time_mode':'replay'}}
            out.write(json.dumps(event,ensure_ascii=False)+'\n')
    return {'read':count,'parsed':parsed,'skipped':count-parsed,'sha256':hashlib.sha256(src.read_bytes()).hexdigest()}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--download',action='store_true');p.add_argument('--limit',type=int,default=2000);a=p.parse_args()
    raw=BASE/'datasets/raw/OpenSSH_2k.log'
    if a.download:
        raw.parent.mkdir(parents=True,exist_ok=True);urllib.request.urlretrieve(SOURCE,raw)
    if not raw.exists():p.error('Source absente : utiliser --download lorsque la connexion Internet est disponible')
    result=prepare(raw,BASE/'datasets/processed/openssh-replay.jsonl',a.limit)
    print(json.dumps(result,indent=2))
