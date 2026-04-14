#!/usr/bin/env python3
# Mirrored from Surge/tools/sync_engine.py
import hashlib
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
import yaml

STATE_FILE = '.sync_state.json'
MANAGED_HEADER = '# AUTO_SYNC_MANAGED: true'
RULESET_HEADER_PREFIX = '# RULESET: '
KNOWN_PREFIXES = ('DOMAIN,','DOMAIN-SUFFIX,','DOMAIN-KEYWORD,','DOMAIN-WILDCARD,','IP-CIDR,','IP-CIDR6,','IP-ASN,','PROCESS-NAME,','DST-PORT,','SRC-IP,','SRC-IP-CIDR,','SRC-PORT,','URL-REGEX,','USER-AGENT,')
NOISE_PREFIXES=('最后更新时间','从Clash自动标准化','从Clash自动同步','从Surge自动同步','原始文件:','规则集:')
TYPE_ORDER={'PROCESS-NAME':10,'DOMAIN':20,'DOMAIN-SUFFIX':30,'DOMAIN-KEYWORD':40,'DOMAIN-WILDCARD':50,'IP-CIDR':60,'IP-CIDR6':70,'IP-ASN':80,'SRC-IP':90,'SRC-IP-CIDR':100,'SRC-PORT':110,'DST-PORT':120,'URL-REGEX':130,'USER-AGENT':140}
DOMAIN_RE=re.compile(r'^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')
WILDCARD_RE=re.compile(r'^\*\.(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')
PROCESS_RE=re.compile(r'^[A-Za-z0-9_.+\-]{1,128}$')
def run(cmd,cwd=None):
 r=subprocess.run(cmd,cwd=str(cwd) if cwd else None,text=True,capture_output=True); 
 if r.returncode!=0: raise RuntimeError(r.stderr or r.stdout); return r.stdout.strip()
def load_state(root):
 p=root/STATE_FILE
 return json.loads(p.read_text()) if p.exists() else {'version':1,'managed_rulesets':{}}
def save_state(root,state): (root/STATE_FILE).write_text(json.dumps(state,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
def normalize_rule(raw):
 raw=raw.strip()
 if not raw or raw.startswith('#'): return None
 for p in KNOWN_PREFIXES:
  if raw.upper().startswith(p): return raw
 try:
  ip=ipaddress.ip_address(raw); return f'IP-CIDR,{raw}/32' if ip.version==4 else f'IP-CIDR6,{raw}/128'
 except: pass
 try:
  net=ipaddress.ip_network(raw,strict=False); return f'IP-CIDR,{raw}' if net.version==4 else f'IP-CIDR6,{raw}'
 except: pass
 if WILDCARD_RE.fullmatch(raw): return f'DOMAIN-WILDCARD,{raw}'
 if DOMAIN_RE.fullmatch(raw): return f'DOMAIN-SUFFIX,{raw}'
 if PROCESS_RE.fullmatch(raw): return f'PROCESS-NAME,{raw}'
 return raw
def stable_rules(rules):
 seen=[]
 for r in rules:
  if r and r not in seen: seen.append(r)
 return sorted(seen,key=lambda x:(TYPE_ORDER.get(x.split(',',1)[0].upper(),9999),x))
def parse_text(content):
 out=[]
 for line in content.splitlines():
  t=line.strip()
  if not t or t in ('payload:','rules:') or any(t.startswith(n) for n in NOISE_PREFIXES) or t.startswith('#'): continue
  if t.startswith('- '): t=t[2:].strip()
  n=normalize_rule(t)
  if n: out.append(n)
 return stable_rules(out)
def parse_clash(content):
 try:
  obj=yaml.safe_load(content)
  if isinstance(obj,dict):
   arr=obj.get('payload') or obj.get('rules')
   if isinstance(arr,list): return stable_rules([normalize_rule(x) for x in arr if isinstance(x,str) and normalize_rule(x)])
 except: pass
 return parse_text(content)
def render_surge(stem,rules): return '\n'.join([MANAGED_HEADER,f'{RULESET_HEADER_PREFIX}{stem}','',*rules,''])
def render_clash(stem,rules): return '\n'.join([MANAGED_HEADER,f'{RULESET_HEADER_PREFIX}{stem}','payload:',*[f'  - {r}' for r in rules],''])
def detect_dir(root,typ):
 for n in ['rules','Rules','rule','Rule','ruleset','RuleSet']:
  p=root/n
  if p.is_dir(): return p
 p=root/('rules' if typ=='surge' else 'ruleset'); p.mkdir(parents=True,exist_ok=True); return p
def scan(root,typ):
 d=detect_dir(root,typ); out={}
 for p in d.iterdir():
  if not p.is_file() or p.name.startswith('.'): continue
  if typ=='surge' and p.suffix: continue
  if typ=='clash' and p.suffix not in ('','.yaml'): continue
  k=p.name if p.suffix=='' else p.stem
  if k in out: raise RuntimeError(f'duplicate stem {k}')
  out[k]=p
 return out,d
def main():
 cur=os.environ['CURRENT_REPO_TYPE']; peer_repo=os.environ['PEER_REPO']; peer_branch=os.environ['PEER_BRANCH']; pat=os.environ['GH_PAT']
 cur_root=Path.cwd(); peer_type='clash' if cur=='surge' else 'surge'; peer_root=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'peer_repo_sync'
 run(['rm','-rf',str(peer_root)]); run(['git','clone',f'https://x-access-token:{pat}@github.com/{peer_repo}.git',str(peer_root)]); run(['git','checkout',peer_branch],cwd=peer_root); run(['git','remote','set-url','origin',f'https://x-access-token:{pat}@github.com/{peer_repo}.git'],cwd=peer_root)
 state=load_state(cur_root); state['managed_rulesets'].update(load_state(peer_root).get('managed_rulesets',{}))
 files,cur_dir=scan(cur_root,cur); _,peer_dir=scan(peer_root,peer_type)
 rulesets={}
 for stem,p in files.items(): rulesets[stem]=parse_text(p.read_text()) if cur=='surge' else parse_clash(p.read_text())
 if not rulesets: raise RuntimeError('No rulesets detected')
 for stem,rules in rulesets.items():
  target=peer_dir/stem; target.write_text(render_surge(stem,rules) if peer_type=='surge' else render_clash(stem,rules))
  state['managed_rulesets'][stem]={'managed_by_system':True,'surge_path':str((cur_dir/stem if cur=='surge' else peer_dir/stem).as_posix()),'clash_path':str((peer_dir/stem if cur=='surge' else cur_dir/stem).as_posix()),'last_synced_from':cur}
 save_state(cur_root,state); save_state(peer_root,state)
 run(['git','config','user.name','autosync-bot'],cwd=peer_root); run(['git','config','user.email','autosync-bot@users.noreply.github.com'],cwd=peer_root); run(['git','add','.'],cwd=peer_root)
 if run(['git','status','--porcelain'],cwd=peer_root): run(['git','commit','-m',f'[AUTO_SYNC] Sync rulesets from {cur} to {peer_type}'],cwd=peer_root); run(['git','push','origin',f'HEAD:{peer_branch}'],cwd=peer_root)
if __name__=='__main__': main()
