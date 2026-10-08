#!/usr/bin/env python3
"""Read-only repeatability and config-generation benchmark on the target router.

Does not start/stop services or measure packet throughput. No saved credentials
or configuration contents are included in the report.
"""
import argparse, hashlib, json, math, platform, statistics, subprocess, sys, tempfile, time
from pathlib import Path

source = Path(__file__).resolve().parents[1] / 'root/usr/lib/atlas'
sys.path.insert(0,str(source if source.is_dir() else Path('/usr/lib/atlas')))
from core import make_config, validate_settings

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',default='/etc/atlas/state.json')
    parser.add_argument('--iterations',type=int,default=100)
    parser.add_argument('--engine',help='Optional path to sing-box for real config checks')
    args=parser.parse_args()
    if not 1 <= args.iterations <= 1000:parser.error('iterations: 1..1000')
    state=json.loads(Path(args.state).read_text())
    state['settings']=validate_settings(state['settings'])
    generation=[];checks=[];digests=set();failures=0
    started=time.perf_counter();cpu_started=time.process_time()
    with tempfile.TemporaryDirectory(prefix='atlas-benchmark-') as directory:
        path=Path(directory)/'config.json'
        for _ in range(args.iterations):
            start=time.perf_counter()
            body=json.dumps(make_config(state),sort_keys=True,separators=(',',':')).encode()
            generation.append((time.perf_counter()-start)*1000)
            digests.add(hashlib.sha256(body).digest())
            if args.engine:
                path.write_bytes(body);start=time.perf_counter()
                result=subprocess.run([args.engine,'check','-c',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
                checks.append((time.perf_counter()-start)*1000)
                failures+=result.returncode!=0
    def summary(samples):
        ordered=sorted(samples)
        return {'median_ms':round(statistics.median(ordered),3),'p95_ms':round(ordered[math.ceil(.95*len(ordered))-1],3),'max_ms':round(max(ordered),3)} if samples else None
    report={'scope':'config_generation_and_optional_engine_check','platform':platform.platform(),
            'iterations':args.iterations,'sections':len(state['settings']['sections']),
            'list_sources':len(state['settings']['remote_lists']), 'generation':summary(generation),
            'engine_check':summary(checks),'engine_check_failures':failures,
            'deterministic_config':len(digests)==1,
            'wall_seconds':round(time.perf_counter()-started,3),'cpu_seconds':round(time.process_time()-cpu_started,3),
            'limitations':['No packet throughput, DNS latency, RAM leak or long-term service stability measurement','No Podkop comparative benchmark']}
    print(json.dumps(report,ensure_ascii=False,indent=2))
    return int(failures>0 or len(digests)!=1)

if __name__=='__main__':
    try:sys.exit(main())
    except Exception:
        print('Benchmark failed: verify state, engine and available resources.',file=sys.stderr)
        sys.exit(1)
