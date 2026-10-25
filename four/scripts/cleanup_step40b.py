from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from firebase_admin import auth, db
from c4security.firebase_util import initialize_admin

TEST_UIDS = [
    "C4_TEST_OPERATOR_A",
    "C4_TEST_OPERATOR_B",
    "C4_TEST_VIEWER_A",
]


def main() -> None:
    initialize_admin()

    for uid in TEST_UIDS:
        try:
            auth.delete_user(uid)
        except Exception:
            pass

    db.reference("/component4_test").delete()
    print("Component 4 Step 40B test users/data removed.")


if __name__ == "__main__":
    main()
