#!/usr/bin/env bash
# Wait until a pending approval has no decision yet, or the job finished; print it.
until python -I -c "
import json,sys
try: a=json.load(open('approvals-pending.json',encoding='utf-8')); d=json.load(open('decisions.json',encoding='utf-8'))
except Exception: sys.exit(1)
sys.exit(0 if any(x['id'] not in d for x in a) else 1)" 2>/dev/null || grep -q job_done run-events.jsonl 2>/dev/null; do sleep 3; done
python -I -c "
import json
d=json.load(open('decisions.json',encoding='utf-8'))
for a in json.load(open('approvals-pending.json',encoding='utf-8')):
  if a['id'] not in d: print(a['description'][:9000]); print('=====')
j=json.load(open('job.json',encoding='utf-8'));print('JOB',j['status']);print('\n'.join(j['logs'][-8:]));print(json.dumps(j.get('result'))[:1500])"
