import 'package:flutter_test/flutter_test.dart';
import 'package:greenhouse_component4_mobile/models/user_access_profile.dart';

void main() {
  group('UserAccessProfile', () {
    test('keeps only explicitly assigned nodes and sorts them', () {
      final profile = UserAccessProfile.fromFirebase(
        uid: 'user-1',
        raw: {
          'role': 'operator',
          'assigned_nodes': {
            'GH_NODE_02': true,
            'GH_NODE_03': false,
            'GH_NODE_01': true,
          },
        },
      );

      expect(profile.assignedNodes, ['GH_NODE_01', 'GH_NODE_02']);
      expect(profile.canControl, isTrue);
    });

    test('defaults unknown profiles to view-only access', () {
      final profile = UserAccessProfile.fromFirebase(
        uid: 'user-2',
        raw: const {},
      );

      expect(profile.role, 'viewer');
      expect(profile.canControl, isFalse);
      expect(profile.assignedNodes, isEmpty);
    });
  });
}
