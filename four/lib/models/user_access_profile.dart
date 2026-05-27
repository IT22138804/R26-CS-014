class UserAccessProfile {
  const UserAccessProfile({
    required this.uid,
    required this.role,
    required this.assignedNodes,
  });

  final String uid;
  final String role;
  final List<String> assignedNodes;

  bool get canControl =>
      role == 'operator' || role == 'manager' || role == 'admin';

  factory UserAccessProfile.fromFirebase({
    required String uid,
    required Map<Object?, Object?> raw,
  }) {
    final role = (raw['role'] ?? 'viewer').toString();
    final assigned = <String>[];
    final nodes = raw['assigned_nodes'];

    if (nodes is Map) {
      for (final entry in nodes.entries) {
        if (entry.value == true) assigned.add(entry.key.toString());
      }
    }

    assigned.sort();
    return UserAccessProfile(
      uid: uid,
      role: role,
      assignedNodes: assigned,
    );
  }
}
