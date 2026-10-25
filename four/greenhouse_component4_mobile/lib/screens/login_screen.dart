import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/material.dart';

import '../services/secure_session_store.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final email = TextEditingController();
  final password = TextEditingController();
  bool busy = false;
  bool hidePassword = true;
  String? error;

  Future<void> login() async {
    FocusScope.of(context).unfocus();
    setState(() {
      busy = true;
      error = null;
    });

    try {
      await FirebaseAuth.instance.signInWithEmailAndPassword(
        email: email.text.trim(),
        password: password.text,
      );
      await SecureSessionStore().refreshAndStoreIdToken();
      password.clear();
    } on FirebaseAuthException catch (e) {
      await SecureSessionStore().clear();
      if (mounted) setState(() => error = e.code);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  void dispose() {
    email.dispose();
    password.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: LayoutBuilder(
          builder: (context, constraints) => SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(24, 24, 24, 32),
            child: ConstrainedBox(
              constraints: BoxConstraints(
                minHeight: constraints.maxHeight - 56,
              ),
              child: Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 440),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Align(
                        child: Container(
                          width: 76,
                          height: 76,
                          decoration: BoxDecoration(
                            color: const Color(0xFFE2F4EA),
                            borderRadius: BorderRadius.circular(24),
                          ),
                          child: const Icon(
                            Icons.eco_rounded,
                            color: Color(0xFF126B49),
                            size: 40,
                          ),
                        ),
                      ),
                      const SizedBox(height: 28),
                      const Text(
                        'Welcome back',
                        textAlign: TextAlign.center,
                        style: TextStyle(
                          fontSize: 30,
                          fontWeight: FontWeight.w800,
                          letterSpacing: -.8,
                        ),
                      ),
                      const SizedBox(height: 8),
                      const Text(
                        'Secure access to your authorized greenhouse nodes',
                        textAlign: TextAlign.center,
                        style: TextStyle(
                          color: Color(0xFF527063),
                          fontSize: 15,
                        ),
                      ),
                      const SizedBox(height: 32),
                      TextField(
                        controller: email,
                        keyboardType: TextInputType.emailAddress,
                        textInputAction: TextInputAction.next,
                        autofillHints: const [AutofillHints.email],
                        decoration: const InputDecoration(
                          labelText: 'Email address',
                          prefixIcon: Icon(Icons.mail_outline_rounded),
                        ),
                      ),
                      const SizedBox(height: 14),
                      TextField(
                        controller: password,
                        obscureText: hidePassword,
                        enableSuggestions: false,
                        autocorrect: false,
                        textInputAction: TextInputAction.done,
                        onSubmitted: busy ? null : (_) => login(),
                        autofillHints: const [AutofillHints.password],
                        decoration: InputDecoration(
                          labelText: 'Password',
                          prefixIcon: const Icon(Icons.lock_outline_rounded),
                          suffixIcon: IconButton(
                            tooltip: hidePassword
                                ? 'Show password'
                                : 'Hide password',
                            onPressed: () =>
                                setState(() => hidePassword = !hidePassword),
                            icon: Icon(
                              hidePassword
                                  ? Icons.visibility_outlined
                                  : Icons.visibility_off_outlined,
                            ),
                          ),
                        ),
                      ),
                      if (error != null) ...[
                        const SizedBox(height: 14),
                        Container(
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: Theme.of(context).colorScheme.errorContainer,
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: Row(
                            children: [
                              const Icon(Icons.error_outline_rounded, size: 20),
                              const SizedBox(width: 10),
                              Expanded(child: Text('Sign in failed: $error')),
                            ],
                          ),
                        ),
                      ],
                      const SizedBox(height: 20),
                      FilledButton.icon(
                        onPressed: busy ? null : login,
                        icon: busy
                            ? const SizedBox.square(
                                dimension: 18,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                ),
                              )
                            : const Icon(Icons.login_rounded),
                        label: Text(
                          busy ? 'Verifying identity...' : 'Sign in securely',
                        ),
                      ),
                      const SizedBox(height: 22),
                      const Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(
                            Icons.shield_outlined,
                            size: 18,
                            color: Color(0xFF527063),
                          ),
                          SizedBox(width: 8),
                          Flexible(
                            child: Text(
                              'Password is never stored on this device',
                              style: TextStyle(
                                color: Color(0xFF527063),
                                fontSize: 13,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
