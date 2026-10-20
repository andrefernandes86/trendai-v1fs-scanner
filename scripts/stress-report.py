#!/usr/bin/env python3
"""Read-only stress report. Decrypts only move evidence; never exports snapshots/credentials."""
import argparse,csv,json,sqlite3,statistics,math,re
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
p=argparse.ArgumentParser();p.add_argument('--data',required=True);p.add_argument('--run',required=True);p.add_argument('--out',required=True);args=p.parse_args()
data,run,out=map(Path,[args.data,args.run,args.out]);out.mkdir(parents=True,exist_ok=True)
c=sqlite3.connect(f'file:{data}/scanner.db?mode=ro',uri=True);c.row_factory=sqlite3.Row
a=AESGCM((data/'master.key').read_bytes())
def instant(v): return datetime.fromisoformat(re.sub(r'(\.\d{6})\d+',r'\1',v).replace('Z','+00:00')).timestamp() if v else None
def delta(a,b): return round(instant(b)-instant(a),6) if a and b else None
def stats(values):
 v=sorted(x for x in values if x is not None)
 return {'count':len(v),'mean':round(statistics.mean(v),3),'p50':round(v[math.ceil(.5*len(v))-1],3),'p95':round(v[math.ceil(.95*len(v))-1],3),'p99':round(v[math.ceil(.99*len(v))-1],3),'max':round(v[-1],3)} if v else {}
summary={}
for uploadsfile in run.glob('*-uploads.json'):
 scenario=uploadsfile.name.removesuffix('-uploads.json');uploads=json.loads(uploadsfile.read_text());records=[]
 for u in uploads:
  row=dict(u);job=c.execute('select * from jobs where key=? order by created_at desc limit 1',(u['key'],)).fetchone()
  row['uploadSeconds']=delta(u['started'],u['finished'])
  if job:
   for k in ['id','state','verdict','digest','destination','error','attempts','created_at','updated_at','size']:row[k]=job[k]
   row['uploadError']=u.get('error','');scan=c.execute('select scanned_at from scan_results where job_id=?',(job['id'],)).fetchone()
   scanning=c.execute("select min(at) from audit where object_id=? and action='job.scanning'",(job['id'],)).fetchone()[0]
   row['discoverySeconds']=delta(u['finished'],job['created_at']);row['queueSeconds']=delta(job['created_at'],scanning)
   row['workerToResponseSeconds']=delta(scanning,scan[0]) if scan else None
   row['routingSeconds']=delta(scan[0],job['updated_at']) if scan else None
   row['endToEndSeconds']=delta(u['started'],job['updated_at']) if job['state'] in ['COMPLETED','QUARANTINED','HELD','RECOVERED'] else None
   move=c.execute('select payload from move_records where job_id=?',(job['id'],)).fetchone()
   if move:
    b=move[0];m=json.loads(a.decrypt(b[:12],b[12:],None))
    row.update({'movePhase':m.get('phase'),'sha256':m.get('sha256'),'crc32c':m.get('crc32c'),'verifiedAt':m.get('verifiedAt')})
   attempts=c.execute('select stage,attempts from stage_attempts where job_id=?',(job['id'],)).fetchall();row['stageFailures']=json.dumps(dict(attempts))
  else: row['state']='NOT_DISCOVERED'
  records.append(row)
 fields=list(dict.fromkeys(k for r in records for k in r));f=out/(scenario+'-files.csv')
 with f.open('w') as handle:
  w=csv.DictWriter(handle,fieldnames=fields);w.writeheader();w.writerows(records)
 finished=[r for r in records if r.get('endToEndSeconds') is not None];elapsed=max((instant(r['updated_at']) for r in finished),default=0)-min(instant(u['started']) for u in uploads)
 summary[scenario]={'files':len(records),'states':dict(Counter(r['state'] for r in records)),'verdicts':dict(Counter(r.get('verdict','') for r in records)),'uploadErrors':sum(bool(u.get('error')) for u in uploads),'finalErrors':sum(bool(r.get('error')) for r in records if r['state'] in ['COMPLETED','QUARANTINED','HELD','RECOVERED']),'movedAndSourceDeleted':sum(r.get('movePhase')=='COMPLETED' for r in records),'checksumEvidence':sum(bool(r.get('crc32c')) and bool(r.get('sha256')) for r in records),'verdictChangesFromOriginal':sum(r.get('verdict')!=r['originalVerdict'] for r in records if r.get('verdict') in ['CLEAN','MALICIOUS','EXCLUDED']),'wallSeconds':round(elapsed,3),'filesPerSecond':round(len(finished)/elapsed,3) if elapsed>0 else None,'latenciesSeconds':{k:stats(r.get(k) for r in records) for k in ['uploadSeconds','discoverySeconds','queueSeconds','workerToResponseSeconds','routingSeconds','endToEndSeconds']}}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
