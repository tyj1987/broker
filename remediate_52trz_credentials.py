import os,re,json,hashlib,py_compile
from pathlib import Path
root=Path(r'E:\Workspaces\52trz-platform\repo')
ctl=Path(r'E:\Workspaces\_control')
expected={
 'apps/business-service/api/database.py':'84333E36663C2386165362C9742A50BCC6A8999E9862398DB355DA2AF95CA843',
 'apps/business-service/api/database.py.orig':'B1EDE6240CB3654B94D5D47FC62B75D129709296E5009FCAA422063532FEA3C3',
 'notes/phase-13/W13.5-SECURITY-P0.md':'518881A3E0E23874D3293FD8EEC5852833D37A88B3D33E8D54AC96E4CE458944',
 'ops/blog/fix-fs-method.py':'F211C1B10164F9A3A86326C6A9254081603BD8AE18746FFE64CCCA5C54170079',
}
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest().upper()
for rel,h in expected.items():
    p=root/rel
    if sha(p)!=h:
        raise SystemExit('concurrent change: '+rel)
before={rel:sha(root/rel) for rel in expected}

for rel in ('apps/business-service/api/database.py','apps/business-service/api/database.py.orig'):
    p=root/rel
    s=p.read_text(encoding='utf-8')
    s2,n1=re.subn(r'(?m)^JWT_SECRET\s*=.*$', 'JWT_SECRET = settings.SECRET_KEY', s, count=1)
    s3,n2=re.subn(r'(?m)^JWT_ALGORITHM\s*=.*$', 'JWT_ALGORITHM = settings.ALGORITHM', s2, count=1)
    if n1!=1 or n2!=1:
        raise SystemExit('JWT structure unexpected: '+rel)
    tmp=p.with_suffix(p.suffix+'.rog-tmp')
    tmp.write_text(s3,encoding='utf-8',newline='')
    os.replace(tmp,p)

p=root/'notes/phase-13/W13.5-SECURITY-P0.md'
lines=p.read_text(encoding='utf-8').splitlines(True)
out=[]
tick=chr(96)
span_re=re.compile(r'\x60[^\x60]*\x60')
for line in lines:
    line=re.sub(r'(?i)(REDIS_PASSWORD=)[^\x60\s)]+', r'\1<REDACTED>', line)
    line=re.sub(r'(?i)(POSTGRES_PASSWORD=)[^\x60\s)]+', r'\1<REDACTED>', line)
    line=re.sub(r'(?i)(root/)[^\x60\s|)]+', r'\1<REDACTED>', line)
    if 'MYSQL_ROOT_PASSWORD' in line:
        spans=list(span_re.finditer(line))
        if len(spans)>1:
            first=spans[0].group(0)
            tail=line[spans[0].end():]
            tail=span_re.sub(tick+'<REDACTED>'+tick,tail)
            line=line[:spans[0].start()]+first+tail
    if 'mysql 密码错填了' in line or ('mysql 密码保留' in line and 'W12' in line):
        line=span_re.sub(tick+'<REDACTED>'+tick,line)
    out.append(line)
p.write_text(''.join(out),encoding='utf-8',newline='')

p=root/'ops/blog/fix-fs-method.py'
s=p.read_text(encoding='utf-8')
start=s.index("# 找 TRZ_FEISHU_SECRET")
end=s.index("insert = ",start)
replacement='''# Find the configuration line by key name only; never embed the secret value.
marker = b"TRZ_FEISHU_SECRET"
idx = raw.find(marker)
if idx < 0:
    print("ERROR: marker not found")
    sys.exit(1)
line_end = raw.find(b"\\n", idx)
insert_at = len(raw) if line_end < 0 else line_end + 1

'''
s2=s[:start]+replacement+s[end:]
s2=s2.replace('new_raw = raw[:idx+len(marker)] + insert + raw[idx+len(marker):]','new_raw = raw[:insert_at] + insert + raw[insert_at:]')
p.write_text(s2,encoding='utf-8',newline='')

for rel in ('apps/business-service/api/database.py','apps/business-service/api/database.py.orig','ops/blog/fix-fs-method.py'):
    py_compile.compile(str(root/rel),doraise=True)

after={rel:sha(root/rel) for rel in expected}
receipt={
 'project':'52trz-platform',
 'action':'redact-hardcoded-credentials',
 'before_sha256':before,
 'after_sha256':after,
 'files':list(expected),
 'backups_created':False,
 'syntax_checks':'passed'
}
(ctl/'52trz-credential-remediation-20260923.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({'changed_files':list(expected),'syntax_checks':'passed','receipt':str(ctl/'52trz-credential-remediation-20260923.json')},ensure_ascii=True))
