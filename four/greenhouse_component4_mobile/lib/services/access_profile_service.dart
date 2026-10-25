import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_database/firebase_database.dart';

import '../models/user_access_profile.dart';

class AccessProfileService {
  AccessProfileService({FirebaseAuth? auth, FirebaseDatabase? database})
    : _auth = auth ?? FirebaseAuth.instance,
      _database = database ?? FirebaseDatabase.instance;

  final FirebaseAuth _auth;
  final FirebaseDatabase _database;

  Future<UserAccessProfile> loadCurrentProfile() async {
    final user = _auth.currentUser;
    if (user == null) throw StateError('Authentication required.');

    final snap = await _database
        .ref('/component4_test/users/${user.uid}')
        .get();

    if (!snap.exists || snap.value is! Map) {
      throw StateError('No Component 4 access profile.');
    }

    return UserAccessProfile.fromFirebase(
      uid: user.uid,
      raw: Map<Object?, Object?>.from(snap.value as Map),
    );
  }

  Future<Map<String, Object?>> loadAssignedNode(String nodeId) async {
    final profile = await loadCurrentProfile();

    // Defense in depth only; Firebase Security Rules remain authoritative.
    if (!profile.assignedNodes.contains(nodeId)) {
      throw StateError('BOLA guard: unauthorized node.');
    }

    final snap = await _database.ref('/component4_test/nodes/$nodeId').get();

    if (!snap.exists || snap.value is! Map) {
      return {'nodeId': nodeId, 'status': 'NO_NODE_DATA'};
    }

    return Map<String, Object?>.from(
      (snap.value as Map).map((key, value) => MapEntry(key.toString(), value)),
    );
  }
}
