from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "lib"

def all_dart():
    return "\n".join(p.read_text(encoding="utf-8") for p in LIB.rglob("*.dart"))

def read(p):
    return (LIB / p).read_text(encoding="utf-8")

def test_secure_storage_package_used():
    assert "FlutterSecureStorage" in read("services/secure_session_store.dart")

def test_no_shared_preferences_package():
    assert "package:shared_preferences" not in all_dart()

def test_password_not_stored():
    text = read("screens/login_screen.dart")
    assert "password.clear()" in text
    assert "FlutterSecureStorage" not in text

def test_id_token_refreshed():
    assert "getIdToken(true)" in read("services/secure_session_store.dart")

def test_auth_state_source_of_truth():
    assert "authStateChanges()" in read("screens/auth_gate.dart")

def test_server_side_profile_read():
    assert "/component4_test/users/${user.uid}" in read("services/access_profile_service.dart")

def test_assigned_nodes_parsed():
    assert "assigned_nodes" in read("models/user_access_profile.dart")

def test_local_bola_guard():
    text = read("services/access_profile_service.dart")
    assert "!profile.assignedNodes.contains(nodeId)" in text

def test_no_direct_actuator_write_path():
    text = all_dart()
    assert "/component4_test/actuator_state" not in text
    assert "client_requests" not in text
