import os, subprocess, shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path

repo = Path('surge_repo')
if repo.exists(): shutil.rmtree(repo)
subprocess.run(['git','clone',f'https://x-access-token:{os.environ["GITHUB_TOKEN"]}@github.com/{os.environ["TARGET_REPO"]}.git','surge_repo'],check=True)
subprocess.run(['git','-C','surge_repo','checkout',os.environ['TARGET_BRANCH']],check=True)

def bj_now():
    return datetime.now(timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S (北京时间)')

changed=False
for p in Path('.').iterdir():
    if not p.is_file() or p.name.startswith('.'):
        continue
    lines=[]
    for raw in p.read_text(encoding='utf-8').splitlines():
        raw=raw.strip()
        if not raw or raw.startswith('#') or raw=='rules:' or raw=='payload:':
            continue
        if raw.startswith('- '): raw=raw[2:]
        lines.append(raw)
    out='# 最后更新时间: '+bj_now()+'\n# 从Clash自动同步\n# 原始文件: '+p.name+'\n'+'\n'.join(lines)+'\n'
    target=repo/p.name
    old=target.read_text(encoding='utf-8') if target.exists() else None
    if old!=out:
        target.write_text(out,encoding='utf-8')
        changed=True

if changed:
    subprocess.run(['git','-C','surge_repo','config','user.name','github-actions[bot]'],check=True)
    subprocess.run(['git','-C','surge_repo','config','user.email','41898282+github-actions[bot]@users.noreply.github.com'],check=True)
    subprocess.run(['git','-C','surge_repo','add','.'],check=True)
    subprocess.run(['git','-C','surge_repo','commit','-m',f'[AUTO_SYNC] 从Clash自动同步规则集 - {bj_now()}'],check=True)
    subprocess.run(['git','-C','surge_repo','push'],check=True)
