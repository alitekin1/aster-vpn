from pathlib import Path
import hashlib, json, re, struct, subprocess
ROOT=Path(__file__).resolve().parents[2];WIN=ROOT/'Windows';OUT=ROOT/'build/windows'
subprocess.run(['go','run','./tools/release','verify','--dir',str(OUT)],cwd=WIN,check=True)
m=json.loads((OUT/'update.json').read_text());files=['update.json','update.json.sig']
for arch,asset in m['assets'].items():
 p=OUT/asset['name'];b=p.read_bytes();assert b[:2]==b'MZ'
 pe=struct.unpack_from('<I',b,0x3c)[0];assert b[pe:pe+4]==b'PE\0\0'
 assert b'requireAdministrator' in b or 'requireAdministrator'.encode('utf-16le') in b,'missing setup UAC manifest'
 assert asset['size']==len(b) and asset['sha256']==hashlib.sha256(b).hexdigest()
 files.append(asset['name'])
(OUT/'SHA256SUMS-Release.txt').write_text(''.join(f'{hashlib.sha256((OUT/f).read_bytes()).hexdigest()}  {f}\n' for f in sorted(files)),encoding='utf-8')
print('PASS: installer PE signatures, UAC manifest, signed asset hashes and complete release checksums.')
