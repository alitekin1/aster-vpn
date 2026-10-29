#!/usr/bin/env python3
"""Reproducible Windows amd64/arm64 build from macOS, Linux, or Windows."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, sys, urllib.request, zipfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
WIN=ROOT/'Windows'
OUT=ROOT/'build'/'windows'
URL='https://www.wintun.net/builds/wintun-0.14.1.zip'
HASH='07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
def run(args,cwd=WIN,env=None):
    subprocess.run(args,cwd=cwd,env=env,check=True)
def prepare_engine():
    target=ROOT/'Engine/.deps/xray'
    patch=ROOT/'Engine/patches/aster_halfclose.go.txt'
    freedom=ROOT/'Engine/patches/freedom-halfclose.py'
    if (target/'common/net/cnc/aster_halfclose.go').exists() and (target/'common/net/cnc/aster_halfclose.go').read_bytes()==patch.read_bytes() and (target/'.aster-freedom-patch').exists() and (target/'.aster-freedom-patch').read_bytes()==freedom.read_bytes(): return
    info=json.loads(subprocess.check_output(['go','mod','download','-json','github.com/xtls/xray-core@v1.260327.0'],cwd=ROOT/'Engine'))
    if target.exists():
        for p in target.rglob('*'):
            if p.is_file():p.chmod(0o644)
        shutil.rmtree(target)
    shutil.copytree(info['Dir'],target)
    for p in target.rglob('*'):
        if p.is_file():p.chmod(0o644)
    shutil.copy2(patch,target/'common/net/cnc/aster_halfclose.go')
    run([sys.executable,str(freedom)],cwd=ROOT/'Engine')
    shutil.copy2(freedom,target/'.aster-freedom-patch')
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--arch',choices=['amd64','arm64','all'],default='all');parser.add_argument('--skip-tests',action='store_true');args=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    prepare_engine();run([sys.executable,'tools/sync_engine.py']);run(['gofmt','-w','internal/packet']);run(['go','mod','download'])
    if not args.skip_tests:
        run(['go','test','./internal/core','./internal/packet','./internal/integration','./internal/update'],env=dict(os.environ,ASTER_LIVE_TEST='0'))
    run(['go','run','./tools/resources'])
    archive=OUT/'wintun-0.14.1.zip'
    if not archive.exists():
        print('Downloading official signed Wintun 0.14.1',flush=True)
        with urllib.request.urlopen(URL,timeout=90) as response: archive.write_bytes(response.read())
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=HASH:raise RuntimeError('Wintun SHA-256 mismatch')
    for arch in (['amd64','arm64'] if args.arch=='all' else [args.arch]):
        label='x64' if arch=='amd64' else 'ARM64';folder=OUT/f'Aster-Windows-{label}'
        if folder.exists():shutil.rmtree(folder)
        folder.mkdir()
        env=dict(os.environ,GOOS='windows',GOARCH=arch,CGO_ENABLED='0')
        print(f'Building Windows {arch}',flush=True)
        run(['go','build','-trimpath','-ldflags=-s -w -H windowsgui','-o',str(folder/'Aster.exe'),'./cmd/aster'],env=env)
        run(['go','test','-c','-o',str(folder/'Aster-Core-Tests.exe'),'./internal/core'],env=env)
        run(['go','test','-c','-o',str(folder/'Aster-Network-Tests.exe'),'./internal/platform'],env=env)
        with zipfile.ZipFile(archive) as z:
            (folder/'wintun.dll').write_bytes(z.read(f'wintun/bin/{arch}/wintun.dll'))
            (folder/'Wintun-LICENSE.txt').write_bytes(z.read('wintun/LICENSE.txt'))
        shutil.copytree(ROOT/'Resources/GeoData',folder/'GeoData')
        shutil.copytree(ROOT/'ThirdPartyLicenses',folder/'Licenses')
        shutil.copy2(WIN/'README.md',folder/'README.md')
        shutil.copy2(WIN/'QUICKSTART-fa.txt',folder/'شروع-از-اینجا.txt')
        shutil.copy2(WIN/'scripts/Install-WebView2.ps1',folder/'Install-WebView2.ps1')
        shutil.copy2(WIN/'scripts/Test-Windows.ps1',folder/'Test-Windows.ps1')
        shutil.copy2(WIN/'THIRD_PARTY_NOTICES.md',folder/'THIRD_PARTY_NOTICES.md')
        shutil.copy2(WIN/'VERIFICATION.md',folder/'VERIFICATION.md')
        # Preserve the licenses of all pinned modules, including the embedded
        # Microsoft loader license, rather than only our direct dependencies.
        stream=subprocess.check_output(['go','list','-m','-json','all'],cwd=WIN).decode()
        decoder=json.JSONDecoder()
        while stream.strip():
            info,offset=decoder.raw_decode(stream.lstrip());stream=stream.lstrip()[offset:]
            source=info.get('Replace',info)
            if not source.get('Dir'):continue
            directory=pathlib.Path(source['Dir'])
            names=[]
            for pattern in ['LICENSE*','COPYING*','NOTICE*']:
                names.extend(p for p in directory.glob(pattern) if p.is_file())
            if info['Path']=='github.com/jchv/go-webview2':
                names.append(directory/'webviewloader/sdk/LICENSE.txt')
            if names:
                dest=folder/'Licenses'/info['Path'].replace('/','_')
                dest.mkdir(exist_ok=True)
                for source_file in names:
                    name=source_file.name if source_file.parent==directory else 'Microsoft-WebView2Loader-LICENSE.txt'
                    shutil.copy2(source_file,dest/name)
        patches=folder/'SourcePatches';patches.mkdir()
        shutil.copy2(ROOT/'Engine/.deps/xray/common/net/cnc/aster_halfclose.go',patches/'aster_halfclose.go')
        shutil.copy2(ROOT/'Engine/.deps/xray/proxy/freedom/freedom.go',patches/'freedom.go')
        shutil.copy2(ROOT/'Engine/patches/freedom-halfclose.py',patches/'freedom-halfclose.py')
        files={str(p.relative_to(folder)).replace(os.sep,'/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.rglob('*')) if p.is_file()}
        (folder/'SHA256SUMS.txt').write_text(''.join(f'{h}  {p}\n' for p,h in files.items()),encoding='utf-8')
        output=OUT/f'Aster-Windows-{label}.zip'
        with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
            for p in sorted(folder.rglob('*')):
                if p.is_file():z.write(p,p.relative_to(OUT))
        print(f'Created {output} ({output.stat().st_size/1024/1024:.1f} MB)',flush=True)
    run([sys.executable,'tools/verify_packages.py','--arch',args.arch])
    print('Compilation and offline tests do not establish Windows live VPN validation.',flush=True)
if __name__=='__main__':main()
