import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureSessionStore {
  SecureSessionStore({
    FirebaseAuth? auth,
    FlutterSecureStorage? storage,
  })  : _auth = auth ?? FirebaseAuth.instance,
        _storage = storage ?? const FlutterSecureStorage(
          aOptions: AndroidOptions(
            encryptedSharedPreferences: true,
          ),
        );

  static const _tokenKey = 'firebase_id_token';
  static const _uidKey = 'firebase_uid';

  final FirebaseAuth _auth;
  final FlutterSecureStorage _storage;

  Future<String> refreshAndStoreIdToken() async {
    final user = _auth.currentUser;
    if (user == null) {
      await clear();
      throw StateError('Authentication required.');
    }

    final token = await user.getIdToken(true);
    if (token == null || token.isEmpty) {
      await clear();
      throw StateError('No Firebase ID token.');
    }

    await _storage.write(key: _tokenKey, value: token);
    await _storage.write(key: _uidKey, value: user.uid);
    return token;
  }

  Future<void> clear() async {
    await _storage.delete(key: _tokenKey);
    await _storage.delete(key: _uidKey);
  }
}
