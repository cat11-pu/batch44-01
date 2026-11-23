import copy

import pytest

import match_result_verifier as mrv


def make(**kwargs):
    return mrv.MatchResultVerifier(**kwargs)


def payload(mid="m1", winner="p1", loser="p2", duration=600,
            reason="normal", ended=1000, kills=None, disconnects=()):
    kills = kills if kills is not None else {winner: 1, loser: 0}
    return {
        "match_id": mid,
        "players": [winner, loser],
        "score": [2, 0] if winner != "draw" else [1, 1],
        "winner": winner,
        "duration": duration,
        "reason": reason,
        "ended_at": ended,
        "kills": kills,
        "disconnects": list(disconnects),
    }


def played(v, data=None, mid="m1"):
    data = data or payload(mid=mid)
    sig = v.sign(data)
    v.submit(mid, data, sig)
    return v.settle(mid)


def test_valid_result_updates_both_ratings_zero_sum():
    v = make()
    out = played(v)
    assert out["status"] == "settled"
    assert out["rated"] is True
    assert v.ratings("p1") > 1000
    assert v.ratings("p2") < 1000
    assert v.ratings("p1") + v.ratings("p2") == 2000


def test_client_kill_count_must_match_server_events():
    v = make()
    v.record_event("m1", {"type": "kill", "actor": "p1", "victim": "p2", "at": 10})
    data = payload(kills={"p1": 9, "p2": 0})
    sig = v.sign(data)
    with pytest.raises(mrv.ResultError) as exc:
        v.submit("m1", data, sig)
    assert exc.value.code == "RESULT_CLIENT_MISMATCH"
    assert v.ratings("p1") == 1000
    assert v.ratings("p2") == 1000


def test_replaying_the_same_result_is_idempotent():
    v = make()
    data = payload()
    sig = v.sign(data)
    v.submit("m1", data, sig)
    first = v.settle("m1")
    after_first = v.ratings("p1")
    with pytest.raises(mrv.ResultError) as exc:
        v.submit("m1", data, sig)
    assert exc.value.code == "RESULT_REPLAY"
    assert v.ratings("p1") == after_first
    assert first["rated"] is True


def test_payload_without_duration_fails_the_signature_scope():
    v = make()
    data = payload()
    data.pop("duration")
    sig = v.sign(data)
    with pytest.raises(mrv.ResultError) as exc:
        v.submit("m1", data, sig)
    assert exc.value.code == "RESULT_SIG_SCOPE"


def test_signature_that_only_covers_player_ids_fails_scope():
    v = make()
    data = payload()
    sig = v.sign({"players": data["players"]})
    with pytest.raises(mrv.ResultError) as exc:
        v.submit("m1", data, sig)
    assert exc.value.code == "RESULT_SIG_SCOPE"


def test_tampering_with_the_score_invalidates_the_signature():
    v = make()
    data = payload()
    sig = v.sign(data)
    data["score"] = [99, 0]
    with pytest.raises(mrv.ResultError):
        v.submit("m1", data, sig)
    assert v.ratings("p1") == 1000


def test_both_sides_submitting_a_result_applies_it_once():
    v = make()
    data = payload(winner="p1", loser="p2")
    sig = v.sign(data)
    v.submit("m1", data, sig)
    v.settle("m1")
    after = v.ratings("p2")
    with pytest.raises(mrv.ResultError) as exc:
        v.submit("m1", data, sig)
    assert exc.value.code == "RESULT_REPLAY"
    assert v.ratings("p2") == after


def test_reconnect_win_after_disconnect_loss_cannot_overwrite_result():
    v = make()
    loss = payload(winner="p1", loser="p2")
    v.submit("m1", loss, v.sign(loss))
    v.settle("m1")
    ratings = (v.ratings("p1"), v.ratings("p2"))
    retry = payload(winner="p2", loser="p1")
    with pytest.raises(mrv.ResultError) as exc:
        v.submit("m1", retry, v.sign(retry))
    assert exc.value.code == "RESULT_REPLAY"
    assert (v.ratings("p1"), v.ratings("p2")) == ratings


def test_absurd_event_damage_is_rejected_at_ingest():
    v = make()
    with pytest.raises(mrv.ResultError):
        v.record_event("m1", {"type": "damage", "actor": "p1",
                              "victim": "p2", "amount": 10 ** 9, "at": 1})
    assert v.audit("m1")["events"] == 0


def test_matches_shorter_than_thirty_seconds_are_not_rated():
    v = make()
    out = played(v, payload(duration=20))
    assert out["rated"] is False
    assert v.ratings("p1") == 1000
    assert v.ratings("p2") == 1000


def test_three_disconnects_void_the_match():
    v = make()
    out = played(v, payload(disconnects=("p3", "p4", "p5")))
    assert out["status"] == "void"
    assert out["rated"] is False
    assert v.ratings("p1") == 1000


def test_older_match_settled_late_does_not_roll_back_ratings():
    v = make()
    newer = payload(mid="m2", ended=2000)
    v.submit("m2", newer, v.sign(newer))
    v.settle("m2")
    snapshot = (v.ratings("p1"), v.ratings("p2"))
    older = payload(mid="m1", ended=1000)
    v.submit("m1", older, v.sign(older))
    out = v.settle("m1")
    assert out["rated"] is False
    assert (v.ratings("p1"), v.ratings("p2")) == snapshot


def test_draw_leaves_both_ratings_unchanged():
    v = make()
    out = played(v, payload(winner="draw", kills={"p1": 3, "p2": 3}))
    assert out["rated"] is False
    assert v.ratings("p1") == 1000
    assert v.ratings("p2") == 1000


def test_rematch_is_not_counted_towards_ratings():
    v = make()
    out = played(v, payload(reason="rematch"))
    assert out["rated"] is False
    assert v.ratings("p1") == 1000


def test_signature_failure_can_be_retried_and_applies_once():
    v = make()
    data = payload()
    with pytest.raises(mrv.ResultError):
        v.submit("m1", data, "not-a-signature")
    assert v.audit("m1")["settled"] is False
    out = played(v, copy.deepcopy(data), mid="m1")
    assert out["status"] == "settled"
    assert v.ratings("p1") > 1000
    with pytest.raises(mrv.ResultError):
        v.settle("m1")
