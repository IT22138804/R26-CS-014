import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/material.dart';
import '../models/user_access_profile.dart';
import '../services/access_profile_service.dart';
import '../services/secure_session_store.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  late Future<UserAccessProfile> profileFuture;
  int pageIndex = 0;

  @override
  void initState() {
    super.initState();
    profileFuture = AccessProfileService().loadCurrentProfile();
  }

  Future<void> refresh() async {
    final next = AccessProfileService().loadCurrentProfile();
    setState(() => profileFuture = next);
    await next;
  }

  Future<void> logout() async {
    await SecureSessionStore().clear();
    await FirebaseAuth.instance.signOut();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Greenhouse Guard', style: TextStyle(fontSize: 20, fontWeight: FontWeight.w800)),
            Text(
              'COMPONENT 4  ·  ZERO TRUST',
              style: TextStyle(color: Color(0xFF527063), fontSize: 10, fontWeight: FontWeight.w700, letterSpacing: 1.1),
            ),
          ],
        ),
        actions: [
          IconButton(tooltip: 'Refresh access', onPressed: refresh, icon: const Icon(Icons.refresh_rounded)),
          IconButton(tooltip: 'Sign out', onPressed: logout, icon: const Icon(Icons.logout_rounded)),
          const SizedBox(width: 6),
        ],
      ),
      body: FutureBuilder<UserAccessProfile>(
        future: profileFuture,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const _LoadingView();
          }
          if (snapshot.hasError) {
            return _ErrorView(message: '${snapshot.error}', onRetry: refresh);
          }
          final profile = snapshot.data!;
          return IndexedStack(
            index: pageIndex,
            children: [
              _Overview(profile: profile, onRefresh: refresh),
              const _SecurityView(),
              _AccessView(profile: profile, onLogout: logout),
            ],
          );
        },
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: pageIndex,
        onDestinationSelected: (value) => setState(() => pageIndex = value),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.dashboard_outlined), selectedIcon: Icon(Icons.dashboard_rounded), label: 'Overview'),
          NavigationDestination(icon: Icon(Icons.shield_outlined), selectedIcon: Icon(Icons.shield_rounded), label: 'Security'),
          NavigationDestination(icon: Icon(Icons.person_outline_rounded), selectedIcon: Icon(Icons.person_rounded), label: 'Access'),
        ],
      ),
    );
  }
}

class _Overview extends StatelessWidget {
  const _Overview({required this.profile, required this.onRefresh});
  final UserAccessProfile profile;
  final Future<void> Function() onRefresh;

  @override
  Widget build(BuildContext context) {
    return RefreshIndicator(
      onRefresh: onRefresh,
      child: ListView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 28),
        children: [
          _AccessBanner(profile: profile),
          const SizedBox(height: 24),
          _SectionTitle(title: 'Authorized nodes', subtitle: '${profile.assignedNodes.length} assigned to your account'),
          const SizedBox(height: 12),
          if (profile.assignedNodes.isEmpty)
            const _EmptyNodes()
          else
            for (final nodeId in profile.assignedNodes) ...[
              _NodeCard(nodeId: nodeId, canControl: profile.canControl),
              const SizedBox(height: 12),
            ],
          const SizedBox(height: 12),
          const _SectionTitle(title: 'Protection status', subtitle: 'Checks applied before actuator execution'),
          const SizedBox(height: 12),
          const _ProtectionGrid(),
          const SizedBox(height: 18),
          const _Notice(
            color: Color(0xFFEAF3FF),
            iconColor: Color(0xFF31689B),
            icon: Icons.verified_outlined,
            text: 'Every node shown is filtered by your server-side profile and re-checked before it is read.',
          ),
        ],
      ),
    );
  }
}

class _AccessBanner extends StatelessWidget {
  const _AccessBanner({required this.profile});
  final UserAccessProfile profile;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: const LinearGradient(colors: [Color(0xFF126B49), Color(0xFF219467)]),
        borderRadius: BorderRadius.circular(24),
        boxShadow: const [BoxShadow(color: Color(0x26126B49), blurRadius: 24, offset: Offset(0, 12))],
      ),
      child: Row(
        children: [
          Container(
            width: 52,
            height: 52,
            decoration: BoxDecoration(color: Colors.white.withOpacity(.16), borderRadius: BorderRadius.circular(16)),
            child: const Icon(Icons.verified_user_rounded, color: Colors.white, size: 28),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Identity verified', style: TextStyle(color: Colors.white70, fontSize: 13)),
                const SizedBox(height: 4),
                Text(
                  profile.role.toUpperCase(),
                  style: const TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.w800, letterSpacing: .5),
                ),
                Text(
                  profile.canControl ? 'Control intents permitted' : 'Read-only access',
                  style: const TextStyle(color: Color(0xFFD9F6E8), fontSize: 13),
                ),
              ],
            ),
          ),
          const Icon(Icons.lock_rounded, color: Color(0xFFD9F6E8)),
        ],
      ),
    );
  }
}

class _NodeCard extends StatelessWidget {
  const _NodeCard({required this.nodeId, required this.canControl});
  final String nodeId;
  final bool canControl;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: FutureBuilder<Map<String, Object?>>(
        future: AccessProfileService().loadAssignedNode(nodeId),
        builder: (context, snapshot) {
          final loading = snapshot.connectionState == ConnectionState.waiting;
          final passed = snapshot.hasData;
          final status = loading ? 'VERIFYING' : (passed ? 'AUTHORIZED' : 'ACCESS FAILED');
          final color = loading
              ? const Color(0xFFB17A19)
              : (passed ? const Color(0xFF147A52) : Theme.of(context).colorScheme.error);
          return Padding(
            padding: const EdgeInsets.all(18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Container(
                      width: 46,
                      height: 46,
                      decoration: BoxDecoration(color: const Color(0xFFE8F5ED), borderRadius: BorderRadius.circular(14)),
                      child: const Icon(Icons.sensors_rounded, color: Color(0xFF147A52)),
                    ),
                    const SizedBox(width: 13),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(nodeId, style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w800)),
                          const SizedBox(height: 4),
                          Row(children: [
                            Container(width: 7, height: 7, decoration: BoxDecoration(color: color, shape: BoxShape.circle)),
                            const SizedBox(width: 6),
                            Text(status, style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w800, letterSpacing: .4)),
                          ]),
                        ],
                      ),
                    ),
                    Chip(
                      avatar: Icon(canControl ? Icons.tune_rounded : Icons.visibility_outlined, size: 16),
                      label: Text(canControl ? 'Intent' : 'View'),
                      visualDensity: VisualDensity.compact,
                    ),
                  ],
                ),
                if (snapshot.hasError) ...[
                  const SizedBox(height: 14),
                  Text('The server rejected this object read. Pull down to verify again.', style: TextStyle(color: color, fontSize: 13)),
                ] else if (passed) ...[
                  const SizedBox(height: 14),
                  const Divider(height: 1),
                  const SizedBox(height: 12),
                  const Row(children: [
                    Icon(Icons.policy_outlined, size: 18, color: Color(0xFF527063)),
                    SizedBox(width: 8),
                    Expanded(child: Text('Ownership checked against assigned nodes', style: TextStyle(color: Color(0xFF527063), fontSize: 13))),
                  ]),
                ],
              ],
            ),
          );
        },
      ),
    );
  }
}

class _ProtectionGrid extends StatelessWidget {
  const _ProtectionGrid();

  @override
  Widget build(BuildContext context) {
    const items = [
      (Icons.badge_outlined, 'BOLA defense', 'Ownership enforced'),
      (Icons.health_and_safety_outlined, 'Safety policy', 'Context checked'),
      (Icons.update_rounded, 'Fresh telemetry', 'Fail-closed'),
      (Icons.replay_rounded, 'Replay defense', 'Duplicate blocked'),
    ];
    return LayoutBuilder(builder: (context, constraints) {
      final tileWidth = (constraints.maxWidth - 10) / 2;
      return Wrap(
        spacing: 10,
        runSpacing: 10,
        children: [
          for (final item in items)
            SizedBox(
              width: tileWidth,
              child: Card(
                child: Padding(
                  padding: const EdgeInsets.all(14),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Icon(item.$1, color: const Color(0xFF147A52), size: 23),
                    const SizedBox(height: 15),
                    Text(item.$2, style: const TextStyle(fontWeight: FontWeight.w700)),
                    Text(item.$3, style: const TextStyle(color: Color(0xFF65776D), fontSize: 12)),
                  ]),
                ),
              ),
            ),
        ],
      );
    });
  }
}

class _SecurityView extends StatelessWidget {
  const _SecurityView();

  @override
  Widget build(BuildContext context) {
    const layers = [
      (Icons.fingerprint_rounded, 'Authentication', 'Firebase identity and refreshed ID token'),
      (Icons.account_tree_outlined, 'Request isolation', 'Intent is separated from actuator execution'),
      (Icons.rule_folder_outlined, 'Database rules', 'Cross-user and direct actuator paths are denied'),
      (Icons.eco_outlined, 'Cyber-physical safety', 'Live conditions are checked before dispatch'),
      (Icons.history_toggle_off_rounded, 'Freshness & replay', 'Stale telemetry and duplicate IDs fail closed'),
    ];
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 28),
      children: [
        const _SectionTitle(title: 'Zero-trust pipeline', subtitle: 'How Component 4 protects each request'),
        const SizedBox(height: 14),
        for (var index = 0; index < layers.length; index++)
          _PipelineStep(number: index + 1, icon: layers[index].$1, title: layers[index].$2, subtitle: layers[index].$3),
        const SizedBox(height: 4),
        const _Notice(
          color: Color(0xFFFFF8E8),
          iconColor: Color(0xFF8A620F),
          icon: Icons.info_outline_rounded,
          text: 'Direct actuator writes remain disabled. This stage displays authorized objects only; sanitized requests arrive in the next validated stage.',
        ),
      ],
    );
  }
}

class _PipelineStep extends StatelessWidget {
  const _PipelineStep({required this.number, required this.icon, required this.title, required this.subtitle});
  final int number;
  final IconData icon;
  final String title;
  final String subtitle;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(children: [
        Container(
          width: 28,
          height: 28,
          alignment: Alignment.center,
          decoration: const BoxDecoration(color: Color(0xFF147A52), shape: BoxShape.circle),
          child: Text('$number', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w800)),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: Card(
            child: ListTile(
              contentPadding: const EdgeInsets.symmetric(horizontal: 15, vertical: 7),
              leading: Icon(icon, color: const Color(0xFF147A52)),
              title: Text(title, style: const TextStyle(fontWeight: FontWeight.w700)),
              subtitle: Text(subtitle),
              trailing: const Icon(Icons.check_circle_rounded, color: Color(0xFF36A873), size: 20),
            ),
          ),
        ),
      ]),
    );
  }
}

class _AccessView extends StatelessWidget {
  const _AccessView({required this.profile, required this.onLogout});
  final UserAccessProfile profile;
  final Future<void> Function() onLogout;

  @override
  Widget build(BuildContext context) {
    final shortUid = profile.uid.length > 16
        ? '${profile.uid.substring(0, 8)}…${profile.uid.substring(profile.uid.length - 6)}'
        : profile.uid;
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 28),
      children: [
        const _SectionTitle(title: 'Access profile', subtitle: 'Server-issued permissions'),
        const SizedBox(height: 14),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(children: [
              const CircleAvatar(
                radius: 34,
                backgroundColor: Color(0xFFE2F4EA),
                child: Icon(Icons.person_rounded, size: 36, color: Color(0xFF126B49)),
              ),
              const SizedBox(height: 14),
              Text(profile.role.toUpperCase(), style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w800)),
              Text(shortUid, style: const TextStyle(color: Color(0xFF65776D))),
              const SizedBox(height: 20),
              const Divider(height: 1),
              const SizedBox(height: 16),
              _ProfileRow(label: 'Assigned nodes', value: '${profile.assignedNodes.length}'),
              const SizedBox(height: 12),
              _ProfileRow(label: 'Permission', value: profile.canControl ? 'Intent control' : 'View only'),
              const SizedBox(height: 12),
              const _ProfileRow(label: 'Session storage', value: 'Encrypted'),
            ]),
          ),
        ),
        const SizedBox(height: 16),
        OutlinedButton.icon(
          onPressed: onLogout,
          style: OutlinedButton.styleFrom(minimumSize: const Size.fromHeight(52)),
          icon: const Icon(Icons.logout_rounded),
          label: const Text('Sign out securely'),
        ),
      ],
    );
  }
}

class _ProfileRow extends StatelessWidget {
  const _ProfileRow({required this.label, required this.value});
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) => Row(children: [
        Expanded(child: Text(label, style: const TextStyle(color: Color(0xFF65776D)))),
        Text(value, style: const TextStyle(fontWeight: FontWeight.w700)),
      ]);
}

class _SectionTitle extends StatelessWidget {
  const _SectionTitle({required this.title, required this.subtitle});
  final String title;
  final String subtitle;

  @override
  Widget build(BuildContext context) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(title, style: const TextStyle(fontSize: 19, fontWeight: FontWeight.w800)),
        const SizedBox(height: 3),
        Text(subtitle, style: const TextStyle(color: Color(0xFF65776D), fontSize: 13)),
      ]);
}

class _Notice extends StatelessWidget {
  const _Notice({required this.color, required this.iconColor, required this.icon, required this.text});
  final Color color;
  final Color iconColor;
  final IconData icon;
  final String text;

  @override
  Widget build(BuildContext context) => Card(
        color: color,
        child: Padding(
          padding: const EdgeInsets.all(18),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Icon(icon, color: iconColor),
            const SizedBox(width: 12),
            Expanded(child: Text(text, style: TextStyle(color: iconColor, height: 1.4))),
          ]),
        ),
      );
}

class _EmptyNodes extends StatelessWidget {
  const _EmptyNodes();

  @override
  Widget build(BuildContext context) => const Card(
        child: Padding(
          padding: EdgeInsets.all(28),
          child: Column(children: [
            Icon(Icons.device_unknown_rounded, size: 42, color: Color(0xFF789086)),
            SizedBox(height: 12),
            Text('No nodes assigned', style: TextStyle(fontWeight: FontWeight.w700)),
            SizedBox(height: 5),
            Text('Ask an administrator to assign a greenhouse node to your account.', textAlign: TextAlign.center),
          ]),
        ),
      );
}

class _LoadingView extends StatelessWidget {
  const _LoadingView();

  @override
  Widget build(BuildContext context) => const Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          CircularProgressIndicator(),
          SizedBox(height: 16),
          Text('Verifying your access…'),
        ]),
      );
}

class _ErrorView extends StatelessWidget {
  const _ErrorView({required this.message, required this.onRetry});
  final String message;
  final Future<void> Function() onRetry;

  @override
  Widget build(BuildContext context) => Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(28),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Icon(Icons.gpp_bad_outlined, size: 56, color: Theme.of(context).colorScheme.error),
            const SizedBox(height: 16),
            const Text('Access could not be verified', style: TextStyle(fontSize: 19, fontWeight: FontWeight.w800)),
            const SizedBox(height: 8),
            Text(message, textAlign: TextAlign.center),
            const SizedBox(height: 20),
            FilledButton.icon(onPressed: onRetry, icon: const Icon(Icons.refresh_rounded), label: const Text('Try again')),
          ]),
        ),
      );
}
