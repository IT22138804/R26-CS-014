from __future__ import annotations
import sys
from pathlib import Path
PROJECT_ROOT=Path(__file__).resolve().parents[1]
SRC=PROJECT_ROOT/'src'
if str(SRC) not in sys.path: sys.path.insert(0,str(SRC))
from c3defense.live_watcher import is_live_operational_state,is_new_packet,live_packet_passed,packet_identity

def current(session='A',sequence=1,timestamp=100): return {'sessionId':session,'sequence':sequence,'timestamp':timestamp}
def test_identity(): assert packet_identity(current('71946649',7,1000)).key=='71946649|7|1000'
def test_duplicate():
    p=current(); assert is_new_packet(p,{packet_identity(p).key}) is False
def test_new_sequence(): assert is_new_packet(current(sequence=2),{packet_identity(current(sequence=1)).key}) is True
def test_live_states():
    assert is_live_operational_state('NORMAL') is True
    assert is_live_operational_state('SECURE_ACTIVE') is True
def test_lockdown_states():
    assert is_live_operational_state('LOCKDOWN') is False
    assert is_live_operational_state('REVOKED_BY_INSIDER_MISUSE') is False
def test_valid_result():
    result={'source':{'freshness':'FRESH','sampleValid':True,'securityValid':True},'mapping':{'status':'PASSED'},'runtimeGuard':{'quarantine':False},'integration':{'decision':'ALLOW_SANITIZED_AI_ANALYSIS_ONLY','actuatorCommandSent':False}}
    passed,failures=live_packet_passed(result); assert passed is True and failures==[]
def test_stale_result():
    result={'source':{'freshness':'STALE_ARCHIVED_SNAPSHOT','sampleValid':True,'securityValid':True},'mapping':{'status':'PASSED'},'runtimeGuard':{'quarantine':False},'integration':{'decision':'ARCHIVED_SNAPSHOT_ANALYSIS_ONLY','actuatorCommandSent':False}}
    passed,failures=live_packet_passed(result); assert passed is False and 'SOURCE_NOT_FRESH' in failures
