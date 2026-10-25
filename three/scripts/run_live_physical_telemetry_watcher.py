from __future__ import annotations
import argparse,json,os,sys,time
from pathlib import Path
import firebase_admin
from dotenv import load_dotenv
from firebase_admin import credentials,db

PROJECT_ROOT=Path(__file__).resolve().parents[1]
SRC=PROJECT_ROOT/'src'
if str(SRC) not in sys.path: sys.path.insert(0,str(SRC))
from c3defense.live_watcher import is_live_operational_state,is_new_packet,live_packet_passed,packet_identity
from c3defense.real_telemetry import DEFAULT_PACKET_INTERVAL_MS,process_component2_snapshot
from c3defense.runtime_guard import load_default_guard

def config():
    load_dotenv(PROJECT_ROOT/'.env')
    cp=Path(os.getenv('FIREBASE_CREDENTIALS_PATH','').strip())
    url=os.getenv('FIREBASE_DATABASE_URL','').strip()
    node=os.getenv('FIREBASE_NODE_ID','GH_NODE_01').strip()
    if not cp.is_absolute(): cp=(PROJECT_ROOT/cp).resolve()
    if not cp.exists(): raise RuntimeError(f'Firebase service-account JSON was not found at: {cp}')
    if not url: raise RuntimeError('FIREBASE_DATABASE_URL is missing from .env')
    return cp,url,node

def init(cp,url):
    try: firebase_admin.get_app(); return
    except ValueError: pass
    firebase_admin.initialize_app(credentials.Certificate(str(cp)),{'databaseURL':url})

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--required-packets',type=int,default=5)
    p.add_argument('--poll-seconds',type=float,default=2.0)
    p.add_argument('--timeout-seconds',type=int,default=180)
    p.add_argument('--max-age-seconds',type=int,default=30)
    p.add_argument('--output',type=Path,default=PROJECT_ROOT/'outputs/step39f2')
    a=p.parse_args()
    cp,url,node=config(); init(cp,url)
    base=f'/greenhouse/{node}'
    guard=load_default_guard(PROJECT_ROOT)
    started=int(time.time()); deadline=time.monotonic()+a.timeout_seconds
    seen=set(); accepted=[]; rejected=[]
    print('='*88)
    print('COMPONENT 3 — STEP 39F-2 LIVE PHYSICAL TELEMETRY WATCHER')
    print('='*88)
    print(f'Node ID                         : {node}')
    print(f'Required fresh packets          : {a.required_packets}')
    print(f'Maximum packet age              : {a.max_age_seconds} seconds')
    print(f'Watcher timeout                 : {a.timeout_seconds} seconds')
    print('Actual actuator commands        : DISABLED')
    print('Waiting for new secure packets from both ESP32 boards...')
    while len(accepted)<a.required_packets and time.monotonic()<deadline:
        current=db.reference(f'{base}/current').get() or {}
        if not isinstance(current,dict) or not current:
            time.sleep(a.poll_seconds); continue
        if not is_new_packet(current,seen):
            time.sleep(a.poll_seconds); continue
        ident=packet_identity(current); seen.add(ident.key)
        state=current.get('systemState','UNKNOWN')
        if not is_live_operational_state(state):
            rejected.append({'identity':ident.key,'systemState':state,'decision':'REJECT_NON_OPERATIONAL_SOURCE_STATE','observedAt':int(time.time())})
            print(f'[SKIP] session={ident.session_id} seq={ident.sequence} state={state}')
            time.sleep(a.poll_seconds); continue
        raw=db.reference(f'{base}/telemetry/raw_stream').get() or {}
        processed=int(time.time())
        result=process_component2_snapshot(guard=guard,current=current,raw_stream=raw,now_epoch=processed,expected_node_id=node,max_sample_age_seconds=a.max_age_seconds,default_packet_interval_ms=DEFAULT_PACKET_INTERVAL_MS).to_dict()
        passed,failures=live_packet_passed(result)
        evidence={**result,'step':'39F-2','processedAt':processed,'liveValidationPassed':passed,'liveValidationFailures':failures,'sourcePath':f'{base}/current','evidenceType':'FRESH_PHYSICAL_COMPONENT2_TELEMETRY','actualActuatorCommands':False,'productionSecurityClaim':False}
        if passed:
            accepted.append(evidence); idx=len(accepted)
            key=f'{idx:03d}_{ident.session_id}_{ident.sequence}_{processed}'.replace('/','_').replace('.','_')
            summary={'step':'39F-2','startedAt':started,'lastProcessedAt':processed,'requiredPackets':a.required_packets,'processedFreshPackets':idx,'rejectedObservations':len(rejected),'lastSessionId':result['source']['sessionId'],'lastSequence':result['source']['sequence'],'lastDecision':result['integration']['decision'],'lastFinalSafeAction':result['integration']['finalSafeAction'],'lastTrustedAiInput':result['integration']['trustedAiInput'],'actualActuatorCommands':False,'evidenceType':'FRESH_PHYSICAL_COMPONENT2_TELEMETRY','productionSecurityClaim':False,'result':'PASSED' if idx==a.required_packets else 'IN_PROGRESS'}
            db.reference(base).update({'component3/live_telemetry/current':evidence,f'component3/live_telemetry/history/{key}':evidence,'component3/summary/step39f2':summary,'system/status/component3LiveTelemetry':'ACTIVE','system/status/component3LiveTelemetryLastUpdate':processed,'system/status/component3LiveTelemetryActuatorCommandSent':False})
            runtime=result.get('runtimeGuard') or {}
            print(f"[PASS {idx}/{a.required_packets}] session={result['source']['sessionId']} seq={result['source']['sequence']} age={result['source']['ageSeconds']}s trigger={runtime.get('trigger_family','NONE')} decision={result['integration']['decision']} action={result['integration']['finalSafeAction']}")
        else:
            rejected.append({'identity':ident.key,'systemState':state,'decision':'REJECT_LIVE_PACKET_VALIDATION_FAILED','failures':failures,'evidence':evidence,'observedAt':processed})
            print(f"[REJECT] session={ident.session_id} seq={ident.sequence} failures={','.join(failures)}")
        time.sleep(a.poll_seconds)
    completed=int(time.time()); final_passed=len(accepted)==a.required_packets
    summary={'step':'39F-2','startedAt':started,'completedAt':completed,'requiredPackets':a.required_packets,'processedFreshPackets':len(accepted),'rejectedObservations':len(rejected),'timeoutSeconds':a.timeout_seconds,'maxAgeSeconds':a.max_age_seconds,'actualActuatorCommands':False,'firebaseReadback':'PENDING','evidenceType':'FRESH_PHYSICAL_COMPONENT2_TELEMETRY','productionSecurityClaim':False,'result':'PASSED' if final_passed else 'REVIEW_REQUIRED'}
    db.reference(f'{base}/component3/summary/step39f2').set(summary)
    rb=db.reference(f'{base}/component3/summary/step39f2').get() or {}
    rb_pass=rb.get('result')==summary['result'] and rb.get('processedFreshPackets')==len(accepted) and rb.get('actualActuatorCommands') is False
    db.reference(f'{base}/component3/summary/step39f2/firebaseReadback').set('PASSED' if rb_pass else 'FAILED')
    a.output.mkdir(parents=True,exist_ok=True)
    (a.output/'live_physical_telemetry_evidence.json').write_text(json.dumps({'summary':{**summary,'firebaseReadback':'PASSED' if rb_pass else 'FAILED'},'acceptedPackets':accepted,'rejectedObservations':rejected,'serviceAccountKeyPrinted':False,'actualActuatorCommands':False},indent=2))
    result_passed=final_passed and rb_pass
    print(); print('='*88); print('COMPONENT 3 — STEP 39F-2 LIVE PHYSICAL TELEMETRY REPORT'); print('='*88)
    print(f'Fresh packets required          : {a.required_packets}')
    print(f'Fresh packets processed         : {len(accepted)}')
    print(f'Rejected observations           : {len(rejected)}')
    print(f"Firebase readback               : {'PASSED' if rb_pass else 'FAILED'}")
    if accepted:
        last=accepted[-1]; runtime=last.get('runtimeGuard') or {}; integ=last['integration']
        print(f"Last source session             : {last['source']['sessionId']}")
        print(f"Last source sequence            : {last['source']['sequence']}")
        print(f"Last source freshness           : {last['source']['freshness']}")
        print(f"Last trigger family             : {runtime.get('trigger_family','NONE')}")
        print(f"Last integration decision       : {integ['decision']}")
        print(f"Last final safe action          : {integ['finalSafeAction']}")
        print(f"Last trusted AI input           : {'YES' if integ['trustedAiInput'] else 'NO'}")
    print('Actual actuator commands        : DISABLED')
    print('Evidence type                   : FRESH_PHYSICAL_COMPONENT2_TELEMETRY')
    print('Production security claim       : NOT YET')
    print(f"STEP 39F-2 RESULT               : {'PASSED' if result_passed else 'REVIEW REQUIRED'}")
    print('='*88)
if __name__=='__main__': main()
