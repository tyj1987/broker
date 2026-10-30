import json
from pathlib import Path
p=Path(r'D:\03_Data\ROG-Migration-Audit\20260923-033102\round2\52trz-stage\filtered-manifest.json')
d=json.loads(p.read_text(encoding='utf-8-sig'))
print(type(d).__name__)
if isinstance(d,dict):
    print(json.dumps({'keys':list(d.keys()),'summary':{k:(len(v) if isinstance(v,(list,dict)) else v) for k,v in d.items() if k not in ('files','entries')}},ensure_ascii=True))
    for k in ('files','entries'):
        if k in d:
            print(k, len(d[k]))
            print(json.dumps(d[k][:5] if isinstance(d[k],list) else list(d[k].items())[:5],ensure_ascii=True))
elif isinstance(d,list):
    print('count',len(d)); print(json.dumps(d[:5],ensure_ascii=True))
