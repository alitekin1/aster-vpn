"""Verify archives, packaged checksums, PE target, GUI/UAC/icon resources."""
from pathlib import Path
import argparse, hashlib, struct, zipfile
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'build/windows'
def pe_resources(raw):
    pe=struct.unpack_from('<I',raw,0x3c)[0]
    assert raw[pe:pe+4]==b'PE\0\0'
    machine,sections=struct.unpack_from('<HH',raw,pe+4)
    optsize=struct.unpack_from('<H',raw,pe+20)[0]
    opt=pe+24
    assert struct.unpack_from('<H',raw,opt)[0]==0x20b
    subsystem=struct.unpack_from('<H',raw,opt+68)[0]
    rva,size=struct.unpack_from('<II',raw,opt+112+16)
    def offset(rva):
        for i in range(sections):
            sec=opt+optsize+i*40
            vs,va,rs,rp=struct.unpack_from('<IIII',raw,sec+8)
            if va<=rva<va+max(vs,rs):return rp+(rva-va)
        raise AssertionError('unmapped RVA')
    base=offset(rva)
    def entries(rel):
        named,ids=struct.unpack_from('<HH',raw,base+rel+12)
        return [struct.unpack_from('<II',raw,base+rel+16+i*8) for i in range(named+ids)]
    types={k for k,v in entries(0)}
    manifests=[]
    def walk(rel):
        for k,v in entries(rel):
            if v&0x80000000:walk(v&0x7fffffff)
            else:
                data,n=struct.unpack_from('<II',raw,base+v)
                manifests.append(raw[offset(data):offset(data)+n])
    for k,v in entries(0):
        if k==24:walk(v&0x7fffffff)
    assert {3,14,16,24}<=types,'missing icon/version/manifest'
    assert any(b'requireAdministrator' in m and b'permonitorv2' in m.lower() for m in manifests),'missing UAC/DPI manifest'
    return machine,subsystem
parser=argparse.ArgumentParser();parser.add_argument('--arch',choices=['amd64','arm64','all'],default='all');args=parser.parse_args()
for label,machine in [('x64',0x8664),('ARM64',0xaa64)]:
    if args.arch!='all' and label!=('x64' if args.arch=='amd64' else 'ARM64'):continue
    folder=OUT/f'Aster-Windows-{label}'
    archive=OUT/f'Aster-Windows-{label}.zip'
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        names=set(z.namelist())
        for line in (folder/'SHA256SUMS.txt').read_text(encoding='utf-8').splitlines():
            expected,name=line.split('  ',1)
            data=(folder/name).read_bytes()
            assert hashlib.sha256(data).hexdigest()==expected,name
            assert z.read(f'{folder.name}/{name}')==data,name
        for suffix in ['Aster.exe','wintun.dll','GeoData/geoip.dat','GeoData/geosite.dat','شروع-از-اینجا.txt','Licenses/github.com_jchv_go-webview2/Microsoft-WebView2Loader-LICENSE.txt','Aster-Core-Tests.exe','Aster-Network-Tests.exe']:
            assert f'{folder.name}/{suffix}' in names,suffix
    target,subsystem=pe_resources((folder/'Aster.exe').read_bytes())
    assert target==machine and subsystem==2,(label,target,subsystem)
    print(f'PASS {label}: ZIP CRC, every package checksum, exact archive content, PE architecture, GUI subsystem, original icon/version and administrator/per-monitor-DPI manifest.')
(OUT/'SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(OUT.glob('Aster-Windows-*.zip'))),encoding='utf-8')
