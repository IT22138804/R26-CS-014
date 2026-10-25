import { useEffect, useState } from "react";
import { onValue, ref } from "firebase/database";
import { database } from "../lib/firebase";

export function useFirebaseValue(path, fallback = null) {
  const [value, setValue] = useState(fallback);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    setError("");

    const dataRef = ref(database, path);

    const unsubscribe = onValue(
      dataRef,
      (snapshot) => {
        setValue(snapshot.exists() ? snapshot.val() : fallback);
        setLoading(false);
      },
      (nextError) => {
        setError(nextError.message || "Firebase read failed.");
        setLoading(false);
      }
    );

    return unsubscribe;
  }, [path]);

  return { value, loading, error };
}
