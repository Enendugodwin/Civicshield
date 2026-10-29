"""Phase 6 test determinism: background protector threads stay off under pytest.

Event hooks still enqueue (notify_event), and tests drain the queue explicitly
via process_queue_sync or call run_protection synchronously. Threading is
exercised on the live server, not in the suite.
"""
import os

os.environ.setdefault("CIVICSHIELD_NO_THREADS", "1")
