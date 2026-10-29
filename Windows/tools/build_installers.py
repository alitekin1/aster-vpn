#!/usr/bin/env python3
"""Compile compact NSIS installers from verified Windows packages."""
from pathlib import Path
import argparse,re,shutil,subprocess,urllib.request
ROOT=Path(__file__).resolve().parents[2];WIN=ROOT/'Windows';OUT=ROOT/'build/windows'
def nsis(s):return str(s).replace('\\','/').replace('$','$$').replace('"','$\\"')
def main():
 p=argparse.ArgumentParser();p.add_argument('--arch',choices=['amd64','arm64','all'],default='all');a=p.parse_args()
 compiler=shutil.which('makensis') or shutil.which('makensis.exe')
 if not compiler:
  for folder in [Path('C:/Program Files (x86)/NSIS'),Path('C:/Program Files/NSIS')]:
   if (folder/'makensis.exe').exists():compiler=str(folder/'makensis.exe');break
 if not compiler:raise RuntimeError('NSIS 3.13+ is required (brew install nsis / choco install nsis).')
 version=re.search(r'const Version = "([0-9.]+)"',(WIN/'internal/buildinfo/version.go').read_text())[1]
 bootstrap=OUT/'MicrosoftEdgeWebview2Setup.exe'
 if not bootstrap.exists():
  print('Downloading the official Microsoft WebView2 bootstrapper',flush=True)
  with urllib.request.urlopen('https://go.microsoft.com/fwlink/p/?LinkId=2124703',timeout=90) as r:bootstrap.write_bytes(r.read())
 if bootstrap.read_bytes()[:2]!=b'MZ' or not 100_000<bootstrap.stat().st_size<10_000_000:raise RuntimeError('Invalid WebView2 bootstrapper')
 for label in (['x64','ARM64'] if a.arch=='all' else ['x64' if a.arch=='amd64' else 'ARM64']):
  package=OUT/f'Aster-Windows-{label}';stage=OUT/f'installer-stage-{label}'
  if stage.exists():shutil.rmtree(stage)
  stage.mkdir()
  # Test programs remain in the portable validation archive, not in the installed app.
  files=[f for f in sorted(package.rglob('*')) if f.is_file() and not f.name.endswith('-Tests.exe') and f.name not in ['SHA256SUMS.txt','Test-Windows.ps1']]
  install=[];uninstall=[];directories=set()
  for f in files:
   rel=f.relative_to(package);parent=str(rel.parent).replace('\\','/')
   target='$INSTDIR' if parent=='.' else '$INSTDIR\\'+parent.replace('/','\\')
   install.extend([f'SetOutPath "{target}"',f'File "{nsis(f)}"'])
   uninstall.append('Delete "$INSTDIR\\'+str(rel).replace('/','\\')+'"')
   for d in rel.parents:
    if str(d)!='.':directories.add(str(d).replace('\\','/'))
  for d in sorted(directories,key=lambda d:d.count('/'),reverse=True):uninstall.append('RMDir "$INSTDIR\\'+d.replace('/','\\')+'"')
  (stage/'install.nsh').write_text('\n'.join(install)+'\n',encoding='utf-8');(stage/'uninstall.nsh').write_text('\n'.join(uninstall)+'\n',encoding='utf-8')
  defs={'VERSION':version,'ARCH':label,'OUTPUT':OUT/f'Aster-Setup-{label}.exe','PAYLOAD':package,'ICON':OUT/'Aster.ico','BOOTSTRAP':bootstrap,'WEBVIEW_SCRIPT':WIN/'installer/Ensure-WebView2.ps1','INSTALL_FILES':stage/'install.nsh','UNINSTALL_FILES':stage/'uninstall.nsh','INSTALLED_KB':str(sum(f.stat().st_size for f in files)//1024)}
  args=[compiler,'-V2','-INPUTCHARSET','UTF8']
  if __import__('os').name=='nt':args=[compiler,'/V2','/INPUTCHARSET','UTF8'];args += ['/D'+k+'='+str(v) for k,v in defs.items()]
  else:args += ['-D'+k+'='+str(v) for k,v in defs.items()]
  subprocess.run(args+[str(WIN/'installer/Aster.nsi')],check=True)
  print('Created '+str(defs['OUTPUT']),flush=True)
if __name__=='__main__':main()
