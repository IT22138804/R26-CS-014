import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/material.dart';

import '../models/user_access_profile.dart';
import '../services/access_profile_service.dart';
import '../services/integrated_demo_service.dart';
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
            Text(
              'Greenhouse Guard',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.w800),
            ),
            Text(
              'COMPONENT 4  ·  ZERO TRUST',
              style: TextStyle(
                color: Color(0xFF527063),
                fontSize: 10,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.1,
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'Refresh access',
            onPressed: refresh,
            icon: const Icon(Icons.refresh_rounded),
          ),
          IconButton(
            tooltip: 'Sign out',
            onPressed: logout,
            icon: const Icon(Icons.logout_rounded),
          ),
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
              const _LiveDemoView(),
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
          NavigationDestination(
            icon: Icon(Icons.dashboard_outlined),
            selectedIcon: Icon(Icons.dashboard_rounded),
            label: 'Overview',
          ),
          NavigationDestination(
            icon: Icon(Icons.play_circle_outline_rounded),
            selectedIcon: Icon(Icons.play_circle_fill_rounded),
            label: 'Live demo',
          ),
          NavigationDestination(
            icon: Icon(Icons.shield_outlined),
            selectedIcon: Icon(Icons.shield_rounded),
            label: 'Security',
          ),
          NavigationDestination(
            icon: Icon(Icons.person_outline_rounded),
            selectedIcon: Icon(Icons.person_rounded),
            label: 'Access',
          ),
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
          _SectionTitle(
            title: 'Authorized nodes',
            subtitle:
                '${profile.assignedNodes.length} assigned to your account',
          ),
          const SizedBox(height: 12),
          if (profile.assignedNodes.isEmpty)
            const _EmptyNodes()
          else
            for (final nodeId in profile.assignedNodes) ...[
              _NodeCard(nodeId: nodeId, canControl: profile.canControl),
              const SizedBox(height: 12),
            ],
          const SizedBox(height: 12),
          const _SectionTitle(
            title: 'Protection status',
            subtitle: 'Checks applied before actuator execution',
          ),
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
        gradient: const LinearGradient(
          colors: [Color(0xFF126B49), Color(0xFF219467)],
        ),
        borderRadius: BorderRadius.circular(24),
        boxShadow: const [
          BoxShadow(
            color: Color(0x26126B49),
            blurRadius: 24,
            offset: Offset(0, 12),
          ),
        ],
      ),
      child: Row(
        children: [
          Container(
            width: 52,
            height: 52,
            decoration: BoxDecoration(
              color: Colors.white.withValues(alpha: .16),
              borderRadius: BorderRadius.circular(16),
            ),
            child: const Icon(
              Icons.verified_user_rounded,
              color: Colors.white,
              size: 28,
            ),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Identity verified',
                  style: TextStyle(color: Colors.white70, fontSize: 13),
                ),
                const SizedBox(height: 4),
                Text(
                  profile.role.toUpperCase(),
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 22,
                    fontWeight: FontWeight.w800,
                    letterSpacing: .5,
                  ),
                ),
                Text(
                  profile.canControl
                      ? 'Control intents permitted'
                      : 'Read-only access',
                  style: const TextStyle(
                    color: Color(0xFFD9F6E8),
                    fontSize: 13,
                  ),
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
          final status = loading
              ? 'VERIFYING'
              : (passed ? 'AUTHORIZED' : 'ACCESS FAILED');
          final color = loading
              ? const Color(0xFFB17A19)
              : (passed
                    ? const Color(0xFF147A52)
                    : Theme.of(context).colorScheme.error);
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
                      decoration: BoxDecoration(
                        color: const Color(0xFFE8F5ED),
                        borderRadius: BorderRadius.circular(14),
                      ),
                      child: const Icon(
                        Icons.sensors_rounded,
                        color: Color(0xFF147A52),
                      ),
                    ),
                    const SizedBox(width: 13),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            nodeId,
                            style: const TextStyle(
                              fontSize: 17,
                              fontWeight: FontWeight.w800,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Row(
                            children: [
                              Container(
                                width: 7,
                                height: 7,
                                decoration: BoxDecoration(
                                  color: color,
                                  shape: BoxShape.circle,
                                ),
                              ),
                              const SizedBox(width: 6),
                              Text(
                                status,
                                style: TextStyle(
                                  color: color,
                                  fontSize: 11,
                                  fontWeight: FontWeight.w800,
                                  letterSpacing: .4,
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                    Chip(
                      avatar: Icon(
                        canControl
                            ? Icons.tune_rounded
                            : Icons.visibility_outlined,
                        size: 16,
                      ),
                      label: Text(canControl ? 'Intent' : 'View'),
                      visualDensity: VisualDensity.compact,
                    ),
                  ],
                ),
                if (snapshot.hasError) ...[
                  const SizedBox(height: 14),
                  Text(
                    'The server rejected this object read. Pull down to verify again.',
                    style: TextStyle(color: color, fontSize: 13),
                  ),
                ] else if (passed) ...[
                  const SizedBox(height: 14),
                  const Divider(height: 1),
                  const SizedBox(height: 12),
                  const Row(
                    children: [
                      Icon(
                        Icons.policy_outlined,
                        size: 18,
                        color: Color(0xFF527063),
                      ),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Ownership checked against assigned nodes',
                          style: TextStyle(
                            color: Color(0xFF527063),
                            fontSize: 13,
                          ),
                        ),
                      ),
                    ],
                  ),
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
    return LayoutBuilder(
      builder: (context, constraints) {
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
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(item.$1, color: const Color(0xFF147A52), size: 23),
                        const SizedBox(height: 15),
                        Text(
                          item.$2,
                          style: const TextStyle(fontWeight: FontWeight.w700),
                        ),
                        Text(
                          item.$3,
                          style: const TextStyle(
                            color: Color(0xFF65776D),
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
          ],
        );
      },
    );
  }
}

class _LiveDemoView extends StatefulWidget {
  const _LiveDemoView();

  @override
  State<_LiveDemoView> createState() => _LiveDemoViewState();
}

class _LiveDemoViewState extends State<_LiveDemoView> {
  final service = IntegratedDemoService();
  DemoScenario component1 = IntegratedDemoService.component1Scenarios.first;
  DemoScenario component2 = IntegratedDemoService.component2Scenarios.first;
  DemoScenario component3 = IntegratedDemoService.component3Scenarios.first;
  int? runningComponent;

  Future<void> run(int component, DemoScenario scenario) async {
    setState(() => runningComponent = component);
    try {
      final requestId = await service.trigger(
        component: component,
        scenario: scenario,
      );
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('${scenario.label} queued · Request $requestId'),
          behavior: SnackBarBehavior.floating,
        ),
      );
    } catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Trigger failed: $error'),
          backgroundColor: Theme.of(context).colorScheme.error,
          behavior: SnackBarBehavior.floating,
        ),
      );
    } finally {
      if (mounted) setState(() => runningComponent = null);
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 28),
      children: [
        const _SectionTitle(
          title: 'Integrated live demonstration',
          subtitle:
              'Firebase → security worker → node result → mobile evidence',
        ),
        const SizedBox(height: 14),
        _SystemConnectionCard(service: service),
        const SizedBox(height: 16),
        _BolaProofCard(service: service),
        const SizedBox(height: 16),
        _DemoControlCard(
          component: 1,
          title: 'Physical access security',
          icon: Icons.contactless_rounded,
          scenarios: IntegratedDemoService.component1Scenarios,
          selected: component1,
          busy: runningComponent == 1,
          onChanged: (value) => setState(() => component1 = value),
          onRun: () => run(1, component1),
          statusPath: '/greenhouse/GH_NODE_01/demo/component1/status',
          service: service,
        ),
        const SizedBox(height: 12),
        _DemoControlCard(
          component: 2,
          title: 'Secure communication',
          icon: Icons.enhanced_encryption_rounded,
          scenarios: IntegratedDemoService.component2Scenarios,
          selected: component2,
          busy: runningComponent == 2,
          onChanged: (value) => setState(() => component2 = value),
          onRun: () => run(2, component2),
          statusPath: '/greenhouse/GH_NODE_01/demo/component2/status',
          service: service,
        ),
        const SizedBox(height: 12),
        _DemoControlCard(
          component: 3,
          title: 'Poisoning defense',
          icon: Icons.psychology_rounded,
          scenarios: IntegratedDemoService.component3Scenarios,
          selected: component3,
          busy: runningComponent == 3,
          onChanged: (value) => setState(() => component3 = value),
          onRun: () => run(3, component3),
          statusPath: '/greenhouse/GH_NODE_01/demo/component3/status',
          service: service,
        ),
        const SizedBox(height: 12),
        _Component4EvidenceCard(service: service),
        const SizedBox(height: 16),
        const _Notice(
          color: Color(0xFFEAF3FF),
          iconColor: Color(0xFF31689B),
          icon: Icons.security_rounded,
          text: 'These are controlled research demonstrations. The mobile app writes only validated demo requests; gateway, safety, and evidence workers remain authoritative.',
        ),
      ],
    );
  }
}

class _SystemConnectionCard extends StatelessWidget {
  const _SystemConnectionCard({required this.service});
  final IntegratedDemoService service;

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<Map<String, Object?>>(
      stream: service.watchMap('/greenhouse/GH_NODE_01/current'),
      builder: (context, snapshot) {
        final data = snapshot.data ?? const <String, Object?>{};
        final connected = snapshot.hasData && data.isNotEmpty;
        return Container(
          padding: const EdgeInsets.all(18),
          decoration: BoxDecoration(
            color: connected
                ? const Color(0xFF126B49)
                : const Color(0xFF52645B),
            borderRadius: BorderRadius.circular(20),
          ),
          child: Row(
            children: [
              Icon(
                connected ? Icons.cloud_done_rounded : Icons.cloud_off_rounded,
                color: Colors.white,
                size: 30,
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      connected
                          ? 'GH_NODE_01 connected'
                          : 'Waiting for GH_NODE_01',
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 16,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    const SizedBox(height: 3),
                    Text(
                      connected
                          ? '${data['systemState'] ?? 'ONLINE'} · Sequence ${data['sequence'] ?? '—'}'
                          : 'Start the integrated host services or simulator',
                      style: const TextStyle(
                        color: Colors.white70,
                        fontSize: 13,
                      ),
                    ),
                  ],
                ),
              ),
              if (snapshot.connectionState == ConnectionState.waiting)
                const SizedBox.square(
                  dimension: 18,
                  child: CircularProgressIndicator(
                    color: Colors.white,
                    strokeWidth: 2,
                  ),
                ),
            ],
          ),
        );
      },
    );
  }
}

class _BolaProofCard extends StatefulWidget {
  const _BolaProofCard({required this.service});
  final IntegratedDemoService service;

  @override
  State<_BolaProofCard> createState() => _BolaProofCardState();
}

class _BolaProofCardState extends State<_BolaProofCard> {
  BolaProof? proof;
  bool busy = false;
  String? error;

  Future<void> runProof() async {
    setState(() {
      busy = true;
      error = null;
      proof = null;
    });
    try {
      final result = await widget.service.runBolaProof();
      if (mounted) setState(() => proof = result);
    } catch (failure) {
      if (mounted) setState(() => error = '$failure');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(17),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Row(
              children: [
                Icon(Icons.policy_rounded, color: Color(0xFF147A52), size: 27),
                SizedBox(width: 11),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'LIVE API SECURITY PROOF',
                        style: TextStyle(
                          color: Color(0xFF147A52),
                          fontSize: 10,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 1,
                        ),
                      ),
                      Text(
                        'BOLA object-access comparison',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            const Text(
              'Use the same Firebase identity to request one assigned node and one tampered node ID.',
              style: TextStyle(color: Color(0xFF65776D), fontSize: 13),
            ),
            const SizedBox(height: 15),
            const _BolaFlowRow(
              number: '1',
              title: 'Authenticated request',
              detail: 'Firebase ID token supplies auth.uid',
            ),
            const _BolaFlowRow(
              number: '2',
              title: 'Object ownership lookup',
              detail: '/users/{uid}/assigned_nodes/{nodeId}',
            ),
            const _BolaFlowRow(
              number: '3',
              title: 'Server-side rule decision',
              detail: 'Allow assigned object · deny changed object ID',
              last: true,
            ),
            const SizedBox(height: 14),
            OutlinedButton.icon(
              onPressed: busy ? null : runProof,
              style: OutlinedButton.styleFrom(
                minimumSize: const Size.fromHeight(50),
              ),
              icon: busy
                  ? const SizedBox.square(
                      dimension: 17,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.science_rounded),
              label: Text(
                busy ? 'Testing both object IDs…' : 'Run BOLA comparison',
              ),
            ),
            if (error != null) ...[
              const SizedBox(height: 12),
              Text(
                'Proof failed to run: $error',
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
            ],
            if (proof != null) ...[
              const SizedBox(height: 14),
              _BolaDecisionRow(
                nodeId: 'GH_NODE_01',
                request: 'Original assigned object',
                passed: proof!.authorizedReadPassed,
                decision: proof!.authorizedReadPassed
                    ? '200 · ALLOWED'
                    : 'FAILED',
              ),
              const SizedBox(height: 8),
              _BolaDecisionRow(
                nodeId: 'GH_NODE_02',
                request: 'Tampered nodeId parameter',
                passed: proof!.unauthorizedReadBlocked,
                decision: proof!.unauthorizedReadBlocked
                    ? proof!.denialCode
                    : 'UNEXPECTEDLY ALLOWED',
              ),
              const SizedBox(height: 12),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: proof!.passed
                      ? const Color(0xFFE8F5ED)
                      : Theme.of(context).colorScheme.errorContainer,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Row(
                  children: [
                    Icon(
                      proof!.passed
                          ? Icons.verified_rounded
                          : Icons.gpp_bad_rounded,
                      color: proof!.passed
                          ? const Color(0xFF147A52)
                          : Theme.of(context).colorScheme.error,
                    ),
                    const SizedBox(width: 9),
                    Expanded(
                      child: Text(
                        proof!.passed
                            ? 'BOLA DEFENSE PASSED · Object ID tampering blocked'
                            : 'BOLA DEFENSE REVIEW REQUIRED',
                        style: const TextStyle(
                          fontWeight: FontWeight.w800,
                          fontSize: 12,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _BolaFlowRow extends StatelessWidget {
  const _BolaFlowRow({
    required this.number,
    required this.title,
    required this.detail,
    this.last = false,
  });
  final String number;
  final String title;
  final String detail;
  final bool last;

  @override
  Widget build(BuildContext context) => Row(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Column(
        children: [
          Container(
            width: 25,
            height: 25,
            alignment: Alignment.center,
            decoration: const BoxDecoration(
              color: Color(0xFF147A52),
              shape: BoxShape.circle,
            ),
            child: Text(
              number,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 11,
                fontWeight: FontWeight.w800,
              ),
            ),
          ),
          if (!last)
            Container(width: 2, height: 24, color: const Color(0xFFD4E7DB)),
        ],
      ),
      const SizedBox(width: 10),
      Expanded(
        child: Padding(
          padding: const EdgeInsets.only(bottom: 10),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                title,
                style: const TextStyle(
                  fontWeight: FontWeight.w700,
                  fontSize: 13,
                ),
              ),
              Text(
                detail,
                style: const TextStyle(color: Color(0xFF65776D), fontSize: 11),
              ),
            ],
          ),
        ),
      ),
    ],
  );
}

class _BolaDecisionRow extends StatelessWidget {
  const _BolaDecisionRow({
    required this.nodeId,
    required this.request,
    required this.passed,
    required this.decision,
  });
  final String nodeId;
  final String request;
  final bool passed;
  final String decision;

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(12),
    decoration: BoxDecoration(
      color: const Color(0xFFF7FAF8),
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: const Color(0xFFE2EBE5)),
    ),
    child: Row(
      children: [
        Icon(
          passed ? Icons.check_circle_rounded : Icons.cancel_rounded,
          color: passed
              ? const Color(0xFF147A52)
              : Theme.of(context).colorScheme.error,
        ),
        const SizedBox(width: 10),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(nodeId, style: const TextStyle(fontWeight: FontWeight.w800)),
              Text(
                request,
                style: const TextStyle(color: Color(0xFF65776D), fontSize: 11),
              ),
            ],
          ),
        ),
        Text(
          decision,
          style: TextStyle(
            color: passed
                ? const Color(0xFF147A52)
                : Theme.of(context).colorScheme.error,
            fontSize: 10,
            fontWeight: FontWeight.w800,
          ),
        ),
      ],
    ),
  );
}

class _DemoControlCard extends StatelessWidget {
  const _DemoControlCard({
    required this.component,
    required this.title,
    required this.icon,
    required this.scenarios,
    required this.selected,
    required this.busy,
    required this.onChanged,
    required this.onRun,
    required this.statusPath,
    required this.service,
  });

  final int component;
  final String title;
  final IconData icon;
  final List<DemoScenario> scenarios;
  final DemoScenario selected;
  final bool busy;
  final ValueChanged<DemoScenario> onChanged;
  final VoidCallback onRun;
  final String statusPath;
  final IntegratedDemoService service;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(17),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Container(
                  width: 42,
                  height: 42,
                  decoration: BoxDecoration(
                    color: const Color(0xFFE8F5ED),
                    borderRadius: BorderRadius.circular(13),
                  ),
                  child: Icon(icon, color: const Color(0xFF147A52)),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'COMPONENT $component',
                        style: const TextStyle(
                          color: Color(0xFF147A52),
                          fontSize: 10,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 1,
                        ),
                      ),
                      Text(
                        title,
                        style: const TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                    ],
                  ),
                ),
                _LiveStatusDot(stream: service.watchMap(statusPath)),
              ],
            ),
            const SizedBox(height: 15),
            DropdownButtonFormField<DemoScenario>(
              initialValue: selected,
              isExpanded: true,
              decoration: const InputDecoration(
                labelText: 'Demonstration scenario',
              ),
              items: [
                for (final scenario in scenarios)
                  DropdownMenuItem(
                    value: scenario,
                    child: Text(scenario.label),
                  ),
              ],
              onChanged: busy
                  ? null
                  : (value) {
                      if (value != null) onChanged(value);
                    },
            ),
            const SizedBox(height: 9),
            Text(
              selected.description,
              style: const TextStyle(color: Color(0xFF65776D), fontSize: 13),
            ),
            const SizedBox(height: 14),
            FilledButton.icon(
              onPressed: busy ? null : onRun,
              icon: busy
                  ? const SizedBox.square(
                      dimension: 17,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.play_arrow_rounded),
              label: Text(busy ? 'Queuing request…' : 'Run demonstration'),
            ),
            const SizedBox(height: 14),
            _ResultSummary(stream: service.watchMap(statusPath)),
          ],
        ),
      ),
    );
  }
}

class _LiveStatusDot extends StatelessWidget {
  const _LiveStatusDot({required this.stream});
  final Stream<Map<String, Object?>> stream;

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<Map<String, Object?>>(
      stream: stream,
      builder: (context, snapshot) {
        final active = snapshot.hasData && snapshot.data!.isNotEmpty;
        return Tooltip(
          message: active ? 'Live result available' : 'Waiting for result',
          child: Container(
            width: 11,
            height: 11,
            decoration: BoxDecoration(
              color: active ? const Color(0xFF36A873) : const Color(0xFFB6C1BB),
              shape: BoxShape.circle,
            ),
          ),
        );
      },
    );
  }
}

class _ResultSummary extends StatelessWidget {
  const _ResultSummary({required this.stream});
  final Stream<Map<String, Object?>> stream;

  @override
  Widget build(BuildContext context) {
    return StreamBuilder<Map<String, Object?>>(
      stream: stream,
      builder: (context, snapshot) {
        if (snapshot.hasError) {
          return Text(
            'Result unavailable: ${snapshot.error}',
            style: TextStyle(
              color: Theme.of(context).colorScheme.error,
              fontSize: 12,
            ),
          );
        }
        final data = snapshot.data ?? const <String, Object?>{};
        if (data.isEmpty) {
          return const Text(
            'No result received yet',
            style: TextStyle(color: Color(0xFF65776D), fontSize: 12),
          );
        }
        final result =
            data['result'] ??
            data['state'] ??
            data['systemState'] ??
            'RECORDED';
        final command = data['command'] ?? 'Latest evaluation';
        return Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: const Color(0xFFF1F7F3),
            borderRadius: BorderRadius.circular(12),
          ),
          child: Row(
            children: [
              const Icon(
                Icons.check_circle_rounded,
                color: Color(0xFF147A52),
                size: 19,
              ),
              const SizedBox(width: 9),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '$result',
                      style: const TextStyle(
                        fontWeight: FontWeight.w800,
                        fontSize: 12,
                      ),
                    ),
                    Text(
                      '$command',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(
                        color: Color(0xFF65776D),
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _Component4EvidenceCard extends StatelessWidget {
  const _Component4EvidenceCard({required this.service});
  final IntegratedDemoService service;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(17),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Row(
              children: [
                Icon(Icons.health_and_safety_rounded, color: Color(0xFF147A52)),
                SizedBox(width: 11),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'COMPONENT 4',
                        style: TextStyle(
                          color: Color(0xFF147A52),
                          fontSize: 10,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 1,
                        ),
                      ),
                      Text(
                        'Live safety evaluation',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            const Text(
              'The integrated Component 4 worker evaluates fresh telemetry every five seconds.',
              style: TextStyle(color: Color(0xFF65776D), fontSize: 13),
            ),
            const SizedBox(height: 14),
            StreamBuilder<Map<String, Object?>>(
              stream: service.watchMap(
                '/greenhouse/GH_NODE_01/component4/latest',
              ),
              builder: (context, snapshot) {
                if (snapshot.hasError) {
                  return Text('Evidence unavailable: ${snapshot.error}');
                }
                final data = snapshot.data ?? const <String, Object?>{};
                if (data.isEmpty) {
                  return const Text('Waiting for the Component 4 worker…');
                }
                return Column(
                  children: [
                    _EvidenceRow(
                      label: 'Result',
                      value: '${data['result'] ?? '—'}',
                    ),
                    _EvidenceRow(
                      label: 'Temperature',
                      value: '${data['temperatureC'] ?? '—'} °C',
                    ),
                    _EvidenceRow(
                      label: 'Soil moisture',
                      value: '${data['soilPct'] ?? '—'} %',
                    ),
                    _EvidenceRow(
                      label: 'Pump decision',
                      value: '${data['pumpOnCandidate'] ?? '—'}',
                    ),
                    _EvidenceRow(
                      label: 'Fan decision',
                      value: '${data['fanOffCandidate'] ?? '—'}',
                    ),
                  ],
                );
              },
            ),
          ],
        ),
      ),
    );
  }
}

class _EvidenceRow extends StatelessWidget {
  const _EvidenceRow({required this.label, required this.value});
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 9),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(
          child: Text(
            label,
            style: const TextStyle(color: Color(0xFF65776D), fontSize: 12),
          ),
        ),
        Flexible(
          child: Text(
            value,
            textAlign: TextAlign.right,
            style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 12),
          ),
        ),
      ],
    ),
  );
}

class _SecurityView extends StatelessWidget {
  const _SecurityView();

  @override
  Widget build(BuildContext context) {
    const layers = [
      (
        Icons.fingerprint_rounded,
        'Authentication',
        'Firebase identity and refreshed ID token',
      ),
      (
        Icons.account_tree_outlined,
        'Request isolation',
        'Intent is separated from actuator execution',
      ),
      (
        Icons.rule_folder_outlined,
        'Database rules',
        'Cross-user and direct actuator paths are denied',
      ),
      (
        Icons.eco_outlined,
        'Cyber-physical safety',
        'Live conditions are checked before dispatch',
      ),
      (
        Icons.history_toggle_off_rounded,
        'Freshness & replay',
        'Stale telemetry and duplicate IDs fail closed',
      ),
    ];
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 28),
      children: [
        const _SectionTitle(
          title: 'Zero-trust pipeline',
          subtitle: 'How Component 4 protects each request',
        ),
        const SizedBox(height: 14),
        for (var index = 0; index < layers.length; index++)
          _PipelineStep(
            number: index + 1,
            icon: layers[index].$1,
            title: layers[index].$2,
            subtitle: layers[index].$3,
          ),
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
  const _PipelineStep({
    required this.number,
    required this.icon,
    required this.title,
    required this.subtitle,
  });
  final int number;
  final IconData icon;
  final String title;
  final String subtitle;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        children: [
          Container(
            width: 28,
            height: 28,
            alignment: Alignment.center,
            decoration: const BoxDecoration(
              color: Color(0xFF147A52),
              shape: BoxShape.circle,
            ),
            child: Text(
              '$number',
              style: const TextStyle(
                color: Colors.white,
                fontWeight: FontWeight.w800,
              ),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Card(
              child: ListTile(
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 15,
                  vertical: 7,
                ),
                leading: Icon(icon, color: const Color(0xFF147A52)),
                title: Text(
                  title,
                  style: const TextStyle(fontWeight: FontWeight.w700),
                ),
                subtitle: Text(subtitle),
                trailing: const Icon(
                  Icons.check_circle_rounded,
                  color: Color(0xFF36A873),
                  size: 20,
                ),
              ),
            ),
          ),
        ],
      ),
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
        const _SectionTitle(
          title: 'Access profile',
          subtitle: 'Server-issued permissions',
        ),
        const SizedBox(height: 14),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              children: [
                const CircleAvatar(
                  radius: 34,
                  backgroundColor: Color(0xFFE2F4EA),
                  child: Icon(
                    Icons.person_rounded,
                    size: 36,
                    color: Color(0xFF126B49),
                  ),
                ),
                const SizedBox(height: 14),
                Text(
                  profile.role.toUpperCase(),
                  style: const TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                Text(
                  shortUid,
                  style: const TextStyle(color: Color(0xFF65776D)),
                ),
                const SizedBox(height: 20),
                const Divider(height: 1),
                const SizedBox(height: 16),
                _ProfileRow(
                  label: 'Assigned nodes',
                  value: '${profile.assignedNodes.length}',
                ),
                const SizedBox(height: 12),
                _ProfileRow(
                  label: 'Permission',
                  value: profile.canControl ? 'Intent control' : 'View only',
                ),
                const SizedBox(height: 12),
                const _ProfileRow(label: 'Session storage', value: 'Encrypted'),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),
        OutlinedButton.icon(
          onPressed: onLogout,
          style: OutlinedButton.styleFrom(
            minimumSize: const Size.fromHeight(52),
          ),
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
  Widget build(BuildContext context) => Row(
    children: [
      Expanded(
        child: Text(label, style: const TextStyle(color: Color(0xFF65776D))),
      ),
      Text(value, style: const TextStyle(fontWeight: FontWeight.w700)),
    ],
  );
}

class _SectionTitle extends StatelessWidget {
  const _SectionTitle({required this.title, required this.subtitle});
  final String title;
  final String subtitle;

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Text(
        title,
        style: const TextStyle(fontSize: 19, fontWeight: FontWeight.w800),
      ),
      const SizedBox(height: 3),
      Text(
        subtitle,
        style: const TextStyle(color: Color(0xFF65776D), fontSize: 13),
      ),
    ],
  );
}

class _Notice extends StatelessWidget {
  const _Notice({
    required this.color,
    required this.iconColor,
    required this.icon,
    required this.text,
  });
  final Color color;
  final Color iconColor;
  final IconData icon;
  final String text;

  @override
  Widget build(BuildContext context) => Card(
    color: color,
    child: Padding(
      padding: const EdgeInsets.all(18),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: iconColor),
          const SizedBox(width: 12),
          Expanded(
            child: Text(text, style: TextStyle(color: iconColor, height: 1.4)),
          ),
        ],
      ),
    ),
  );
}

class _EmptyNodes extends StatelessWidget {
  const _EmptyNodes();

  @override
  Widget build(BuildContext context) => const Card(
    child: Padding(
      padding: EdgeInsets.all(28),
      child: Column(
        children: [
          Icon(
            Icons.device_unknown_rounded,
            size: 42,
            color: Color(0xFF789086),
          ),
          SizedBox(height: 12),
          Text(
            'No nodes assigned',
            style: TextStyle(fontWeight: FontWeight.w700),
          ),
          SizedBox(height: 5),
          Text(
            'Ask an administrator to assign a greenhouse node to your account.',
            textAlign: TextAlign.center,
          ),
        ],
      ),
    ),
  );
}

class _LoadingView extends StatelessWidget {
  const _LoadingView();

  @override
  Widget build(BuildContext context) => const Center(
    child: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        CircularProgressIndicator(),
        SizedBox(height: 16),
        Text('Verifying your access…'),
      ],
    ),
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
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.gpp_bad_outlined,
            size: 56,
            color: Theme.of(context).colorScheme.error,
          ),
          const SizedBox(height: 16),
          const Text(
            'Access could not be verified',
            style: TextStyle(fontSize: 19, fontWeight: FontWeight.w800),
          ),
          const SizedBox(height: 8),
          Text(message, textAlign: TextAlign.center),
          const SizedBox(height: 20),
          FilledButton.icon(
            onPressed: onRetry,
            icon: const Icon(Icons.refresh_rounded),
            label: const Text('Try again'),
          ),
        ],
      ),
    ),
  );
}
