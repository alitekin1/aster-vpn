#!/usr/bin/env python3
"""Produce an explicitly allowlisted, secret-scanned public source snapshot.
Never publish this project's working-tree history or arbitrary untracked files.
"""
from pathlib import Path
import argparse,hashlib,re,shutil
ROOT=Path(__file__).resolve().parents[2]
WINDOWS_EXT={'.go','.mod','.sum','.py','.js','.cjs','.css','.html','.nsi','.ps1','.sh'}
DOCS={'README.md','UPDATES.md','RELEASE_NOTES.md','QUICKSTART-fa.txt','THIRD_PARTY_NOTICES.md','VERIFICATION.md'}
SECRETS={
 'private-key':re.compile(rb'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----'),
 'github-token':re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b'),
 'api-key':re.compile(rb'\bsk-(?:proj-)?[A-Za-z0-9_-]{30,}\b'),
 'aws-key':re.compile(rb'\bAKIA[A-Z0-9]{16}\b'),
 'home-path':re.compile(rb'/Users/[A-Za-z0-9_.-]+/'),
}
def main():
 p=argparse.ArgumentParser();p.add_argument('--destination',type=Path,default=ROOT/'build/publish/aster-vpn');args=p.parse_args();dest=args.destination.resolve()
 files={}
 for source in (ROOT/'Windows').rglob('*'):
  if not source.is_file() or any(part in {'__pycache__','.git'} for part in source.parts):continue
  rel=source.relative_to(ROOT);relative=source.relative_to(ROOT/'Windows')
  if relative.parts[0]=='internal' and relative.parts[1:2]==('packet',):continue
  if source.suffix in WINDOWS_EXT or relative.as_posix() in DOCS:files[rel.as_posix()]=source.read_bytes()
 for relative in ['Engine/main.go','Engine/main_test.go','Engine/go.mod','Engine/go.sum','Engine/patches/aster_halfclose.go.txt','Engine/patches/freedom-halfclose.py','THIRD_PARTY_NOTICES.md']:
  files[relative]=(ROOT/relative).read_bytes()
 for directory in ['Resources/GeoData','ThirdPartyLicenses','.github/workflows']:
  for source in (ROOT/directory).rglob('*'):
   if source.is_file():files[source.relative_to(ROOT).as_posix()]=source.read_bytes()
 icon='Sources/AsterApp/Assets.xcassets/AppIcon.appiconset/icon-256.png';files[icon]=(ROOT/icon).read_bytes()
 files['README.md']=b'''# Aster for Windows\n\nA Windows Xray VPN client with Smart Iran routing, an installer and authenticated in-app updates.\n\n- [Download x64 setup](https://github.com/alitekin1/aster-vpn/releases/latest/download/Aster-Setup-x64.exe) for Intel/AMD Windows.\n- [Download ARM64 setup](https://github.com/alitekin1/aster-vpn/releases/latest/download/Aster-Setup-ARM64.exe) for ARM Windows.\n- [Installation and features](Windows/README.md)\n- [Update security and publishing](Windows/UPDATES.md)\n- [Verification](Windows/VERIFICATION.md)\n\nSettings -> Application updates -> Check for updates downloads and installs verified releases without a GitHub token. Updates preserve your encrypted settings. The VPN briefly disconnects while updating.\n\nNo VPN access, subscription URLs, user settings, logs, signing private keys or unrelated local history are included. Bring your own server configuration. Only the Windows source, shared packet engine, build resources and upstream routing datasets are published.\n\nBuild with Go 1.26+, Python 3 and NSIS 3+: `python Windows/tools/build.py`, then `python Windows/tools/build_installers.py`. See the update guide for signed publishing.\n'''
 files['.gitignore']=b'''build/\nEngine/.deps/\nWindows/internal/packet/engine.go\nWindows/internal/packet/engine_test.go\nWindows/cmd/aster/*.syso\n*.exe\n*.dll\n*.pem\n*.key\n.env*\nstate.dat\nstate.json\n*.log\n__pycache__/\n.DS_Store\n.aster-publish-root\n'''
 files['.gitattributes']=b'* text=auto\n*.go text eol=lf\n*.py text eol=lf\n*.sh text eol=lf\n*.ps1 text eol=crlf\n'
 violations=[]
 for name,data in files.items():
  if name.endswith(('.dat','.png')):continue
  for kind,pattern in SECRETS.items():
   if pattern.search(data):violations.append(f'{name}: {kind}')
 if violations:raise RuntimeError('Publication stopped; inspect these files (contents withheld):\n'+'\n'.join(violations))
 if dest.exists() and not (dest/'.aster-publish-root').exists():raise RuntimeError('Refusing to overwrite a directory not created by this publisher')
 dest.mkdir(parents=True,exist_ok=True);(dest/'.aster-publish-root').write_text('Sanitized Aster publication snapshot.\n')
 for old in dest.rglob('*'):
  if old.is_file() and not any(p in {'.git','.deps','build','__pycache__'} for p in old.relative_to(dest).parts) and old.name!='.aster-publish-root' and old.relative_to(dest).as_posix() not in files:old.unlink()
 for name,data in files.items():
  target=dest/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
 print(f'PASS: {len(files)} allowlisted files; private keys/tokens/home paths absent; local app data and history excluded.')
 print(f'Publication snapshot: {dest}')
if __name__=='__main__':main()
