import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_database/firebase_database.dart';
import 'package:http/http.dart' as http;

class DemoScenario {
  const DemoScenario(this.command, this.label, this.description);

  final String command;
  final String label;
  final String description;
}

class BolaProof {
  const BolaProof({
    required this.uid,
    required this.authorizedReadPassed,
    required this.unauthorizedReadBlocked,
    required this.denialCode,
    required this.completedAt,
  });

  final String uid;
  final bool authorizedReadPassed;
  final bool unauthorizedReadBlocked;
  final String denialCode;
  final DateTime completedAt;

  bool get passed => authorizedReadPassed && unauthorizedReadBlocked;
}

class IntegratedDemoService {
  IntegratedDemoService({FirebaseDatabase? database, FirebaseAuth? auth})
    : _database = database ?? FirebaseDatabase.instance,
      _auth = auth ?? FirebaseAuth.instance;

  final FirebaseDatabase _database;
  final FirebaseAuth _auth;

  static const component1Scenarios = [
    DemoScenario(
      'DEMO_AUTHORIZED_UNLOCK',
      'Authorized RFID',
      'Validate an approved card and protected-sector evidence.',
    ),
    DemoScenario(
      'DEMO_WRONG_CARD',
      'Wrong RFID card',
      'Reject an unauthorized card before actuator access.',
    ),
    DemoScenario(
      'DEMO_RFID_CLONE',
      'RFID clone attempt',
      'Detect a copied UID with invalid protected-sector proof.',
    ),
    DemoScenario(
      'DEMO_INSIDER_MISUSE',
      'Insider misuse',
      'Exercise attribution, lockdown, and safe relay state.',
    ),
  ];

  static const component2Scenarios = [
    DemoScenario(
      'TEST_REPLAY',
      'Replay packet',
      'Reject an old authenticated sequence.',
    ),
    DemoScenario(
      'TEST_INVALID_HMAC',
      'Modified packet',
      'Reject a packet before decryption.',
    ),
    DemoScenario(
      'TEST_INVALID_GCM',
      'Invalid GCM tag',
      'Fail authenticated decryption.',
    ),
    DemoScenario(
      'TEST_STALE_TIMESTAMP',
      'Stale timestamp',
      'Fail the freshness window.',
    ),
    DemoScenario(
      'TEST_HMAC_SPIKE',
      'HMAC failure spike',
      'Reach the session-revoke threshold.',
    ),
    DemoScenario(
      'ROTATE_SESSION',
      'Rotate session',
      'Rotate runtime session keys safely.',
    ),
    DemoScenario(
      'REVOKE_SESSION',
      'Emergency revoke',
      'Revoke and zeroize runtime keys.',
    ),
  ];

  static const component3Scenarios = [
    DemoScenario(
      'C3_RUN_FULL_SUITE',
      'Full defense suite',
      'Run all controlled poison-defense cases.',
    ),
    DemoScenario(
      'C3_NORMAL_DAYLIGHT',
      'Normal daylight',
      'Validate a clean baseline sample.',
    ),
    DemoScenario(
      'C3_EXACT_BACKDOOR',
      'Exact backdoor',
      'Detect the known trigger family.',
    ),
    DemoScenario(
      'C3_JITTERED_BACKDOOR',
      'Jittered backdoor',
      'Detect a varied trigger pattern.',
    ),
    DemoScenario(
      'C3_SLOW_POISON',
      'Slow poisoning',
      'Detect gradual training-data manipulation.',
    ),
    DemoScenario(
      'C3_CLEAN_DARK',
      'Clean darkness',
      'Avoid a false positive on valid darkness.',
    ),
    DemoScenario(
      'C3_HOT_DAYLIGHT',
      'Hot daylight',
      'Evaluate a valid environmental edge case.',
    ),
  ];

  Stream<Map<String, Object?>> watchMap(String path) {
    return _database.ref(path).onValue.map((event) {
      final value = event.snapshot.value;
      if (value is! Map) return <String, Object?>{};
      return value.map((key, item) => MapEntry(key.toString(), item));
    });
  }

  Future<String> trigger({
    required int component,
    required DemoScenario scenario,
  }) async {
    if (component < 1 || component > 3) {
      throw ArgumentError.value(
        component,
        'component',
        'Only Components 1–3 have demo triggers.',
      );
    }

    final requestId = DateTime.now().millisecondsSinceEpoch.toString();
    await _database.ref('/demo/component$component/pending').set({
      'command': scenario.command,
      'requestId': requestId,
      'requestedAt': DateTime.now().millisecondsSinceEpoch ~/ 1000,
      'requestedBy': 'COMPONENT${component}_DASHBOARD',
    });
    return requestId;
  }

  Future<BolaProof> runBolaProof() async {
    final user = _auth.currentUser;
    if (user == null) throw StateError('Authentication required.');

    // Use REST instead of the native DatabaseReference.get() cache so this is
    // an unambiguous server authorization test with visible HTTP status codes.
    final token = await user.getIdToken(true);
    final databaseUrl = Firebase.app().options.databaseURL;
    if (token == null || databaseUrl == null) {
      throw StateError('Firebase REST configuration is unavailable.');
    }

    Future<http.Response> readNode(String nodeId) {
      final uri = Uri.parse('$databaseUrl/component4_test/nodes/$nodeId.json')
          .replace(queryParameters: {'auth': token});
      return http.get(uri);
    }

    final assigned = await readNode('GH_NODE_01');
    final tampered = await readNode('GH_NODE_02');
    final authorizedReadPassed = assigned.statusCode == 200;
    final unauthorizedReadBlocked =
        tampered.statusCode == 401 || tampered.statusCode == 403;
    final denialCode = unauthorizedReadBlocked
        ? '${tampered.statusCode} · PERMISSION_DENIED'
        : '${tampered.statusCode} · UNEXPECTED_RESPONSE';

    return BolaProof(
      uid: user.uid,
      authorizedReadPassed: authorizedReadPassed,
      unauthorizedReadBlocked: unauthorizedReadBlocked,
      denialCode: denialCode,
      completedAt: DateTime.now(),
    );
  }
}
