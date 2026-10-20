#!/usr/bin/env python3
"""Authenticated Event Grid ingestion load driver. This does not measure scanner throughput."""
import argparse,concurrent.futures,json,os,time,urllib.request,uuid
p=argparse.ArgumentParser();p.add_argument('--url',required=True);p.add_argument('--account',required=True);p.add_argument('--container',required=True);p.add_argument('--manifest',required=True,help='JSON array of pre-uploaded real blob records: key, etag, size, version');p.add_argument('--count',type=int,default=1000);p.add_argument('--concurrency',type=int,default=32);p.add_argument('--duration',type=float,default=0);p.add_argument('--duplicate-every',type=int,default=10);a=p.parse_args()
token=os.environ['EVENT_INGEST_TOKEN'];files=json.load(open(a.manifest));assert files,'manifest is empty';started=time.monotonic()
def send(i):
 f=files[i%len(files)];ev={'id':str(uuid.uuid4()),'eventType':'Microsoft.Storage.BlobCreated','data':{'api':'PutBlockList','url':f'https://{a.account}.blob.core.windows.net/{a.container}/{f["key"]}','eTag':f['etag'],'contentLength':f['size'],'versionId':f.get('version','')}}
 if a.duration:time.sleep(max(0,started+i*a.duration/a.count-time.monotonic()))
 payload=[ev,ev] if a.duplicate_every and i%a.duplicate_every==0 else [ev]
 req=urllib.request.Request(a.url.rstrip('/')+'/api/eventgrid',data=json.dumps(payload).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=60) as r:return r.status
with concurrent.futures.ThreadPoolExecutor(a.concurrency) as ex:
 codes=list(ex.map(send,range(a.count)))
print(json.dumps({'requests':len(codes),'elapsedSeconds':time.monotonic()-started,'accepted':codes.count(202),'measurement':'ingestion HTTP only; not Vision One throughput'}))
