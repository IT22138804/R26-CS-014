import { createContext, useContext, useEffect, useMemo, useState } from "react";
import {
  onAuthStateChanged,
  signInWithEmailAndPassword,
  signOut
} from "firebase/auth";
import { auth } from "../lib/firebase";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (nextUser) => {
      setUser(nextUser);
      setAuthLoading(false);
    });

    return unsubscribe;
  }, []);

  const value = useMemo(
    () => ({
      user,
      authLoading,
      login: (username, password) => {
        const email = username.trim().toLowerCase() === "admin"
          ? "ghouse.dashboard@gmail.com"
          : username.trim();
        return signInWithEmailAndPassword(auth, email, password);
      },
      logout: () => signOut(auth)
    }),
    [user, authLoading]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used inside AuthProvider");
  }

  return context;
}
