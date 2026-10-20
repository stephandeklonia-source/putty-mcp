import threading
import time

from putty_lib.approvals import SECRET, TOOL, ApprovalQueue


def make():
    events = []
    return ApprovalQueue(lambda kind, **d: events.append(d)), events


def answer_later(q, **kw):
    def run():
        for _ in range(100):
            pending = q.pending()
            if pending:
                q.decide(pending[0]["approval_id"], **kw)
                return
            time.sleep(0.01)
    threading.Thread(target=run, daemon=True).start()


def test_approve_with_remember_filtered_to_offered_options():
    q, events = make()
    answer_later(q, approved=True, remember=["host:a", "host:evil"])
    a = q.request(TOOL, "t", {}, timeout=5, options=[{"id": "host:a", "label": "x"}])
    assert a.approved and a.remember == ["host:a"]
    assert [e["status"] for e in events] == ["waiting", "approved"]


def test_timeout_denies():
    q, _ = make()
    a = q.request(TOOL, "t", {}, timeout=0.2)
    assert a.approved is False and "no decision" in a.reason and q.pending() == []


def test_deny_all():
    q, _ = make()
    threading.Timer(0.1, lambda: q.deny_all("kill switch")).start()
    a = q.request(TOOL, "t", {}, timeout=5)
    assert a.approved is False and a.reason == "kill switch"


def test_secret_needs_a_value_and_is_not_public():
    q, _ = make()
    result = {}

    def run():
        result["a"] = q.request(SECRET, "pw", {"confirm": True}, timeout=5)

    t = threading.Thread(target=run)
    t.start()
    while not q.pending():
        time.sleep(0.01)
    aid = q.pending()[0]["approval_id"]
    assert q.decide(aid, True) is False  # no secret given
    assert q.pending()[0]["approval_id"] == aid
    assert q.decide(aid, True, secret="hunter2")
    t.join()
    assert result["a"].secret == "hunter2"
    assert "hunter2" not in str(result["a"].public()) and "hunter2" not in repr(result["a"])
