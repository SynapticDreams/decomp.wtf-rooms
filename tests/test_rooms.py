"""The list's keeper, against rooms that answer as decomp.wtf's do (signed with each room's key)."""

import base64
import json
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import rooms  # noqa: E402

# A listing decomp.wtf wrote and signed (its roomlist.py): both sides must write the signed text alike.
FROM_THE_APP = (
    "decomp.wtf-listing:eyJhY3Rpb24iOiJsaXN0Iiwia2V5IjoiTjRVSHlVU1V2R0d4TEFZaHJWTTg0WDlnTVpxZlJzR3VYLUdtVGZnanBZayIs"
    "InJvb20iOiJkZW1vIiwidCI6MTc5MDAwMDAwMCwiZ2lzdCI6IjAxMjM0NTY3ODlhYmNkZWYwMTIzIiwidXJsIjoiIiwicGxhdGZvcm0iOiJuNjQi"
    "LCJzaGExIjoiYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYSIsImNvZGUiOiJORFFFIiwia2luZCI6InJvbSIsInJlcG8i"
    "OiIiLCJub3RlIjoic3RhcnRpbmcgd2l0aCB0aGUgbWVudXMiLCJzaWciOiJMS1BBZlROY3RjdzJaRXpzWW4tVGdMWFlGRDdEbG5GQ0Y5X0JyeE15"
    "YnY0ZU1KRE83ZlFEVkhGTjM5ZllrOE9TaG1YOXFTdG9xZU5ZUUI2WFJ3TjVDUSJ9")

NOW = 1790000000


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Room:
    """A decomp.wtf room as the list sees it: its key, its gist, what it says at its address."""

    def __init__(self, url="https://abc-def.trycloudflare.com", visibility="public", gist="0123456789abcdef0123",
                 sha1="a" * 40, code="NDQE", platform="n64"):
        self.secret = Ed25519PrivateKey.generate()
        self.key = b64(self.secret.public_key().public_bytes_raw())
        self.url, self.visibility, self.gist = url, visibility, gist
        self.hello = {"kind": "rom", "sha1": sha1, "game_code": code, "platform": platform, "functions": 120,
                      "matched": 30, "members": 3, "limit": 0, "approve": True}
        self.up, self.note_expires = True, NOW + 86400

    def sign(self, text: str) -> str:
        return b64(self.secret.sign(text.encode()))

    def listing(self, action="list", t=NOW, **change) -> str:
        fields = {"action": action, "key": self.key, "room": "demo", "t": t}
        if action == "list":
            fields |= {"gist": self.gist, "url": "", "platform": self.hello["platform"], "sha1": self.hello["sha1"],
                       "code": self.hello["game_code"], "kind": "rom", "repo": "", "note": "menus first"}
        fields |= change
        signed = {**fields, "sig": self.sign(rooms.listing_message(fields))}
        return "Listing\n\n" + "decomp.wtf-listing:" + b64(json.dumps(signed).encode()) + "\n"

    def answer(self, url: str) -> tuple[int, dict]:
        if url.startswith(f"{rooms.GITHUB}/gists/{self.gist}"):
            note = {"url": self.url, "t": NOW - 60, "expires": self.note_expires}
            note["sig"] = self.sign(rooms.pointer_message(self.key, self.url, note["t"], note["expires"]))
            return 200, {"files": {rooms.NOTE: {"content": json.dumps(note)}}}
        if not self.up or not url.startswith(self.url):
            return 0, {}
        q = dict(p.split("=", 1) for p in url.split("?", 1)[1].split("&"))
        if "/collab/ping" in url:
            return 200, {"key": self.key, "signature": self.sign(rooms.ping_message(self.url, q["room"], q["nonce"]))}
        if self.visibility != "public":
            return 400, {"error": "this invite link is no longer valid"}
        return 200, {**self.hello, "visibility": "public"}


@pytest.fixture
def lists(tmp_path, monkeypatch):
    for name in ("ROOMS", "LEDGER", "BLOCKED", "REPLY"):
        monkeypatch.setattr(rooms, name, tmp_path / getattr(rooms, name).name)
    monkeypatch.setattr(rooms, "public_address", lambda url: None)
    out = []

    def use(*rs):
        monkeypatch.setattr(rooms, "fetch", lambda url, headers=None, timeout=20: next(
            (r.answer(url) for r in rs if url.startswith(r.url) or r.gist in url), (0, {})))
        out.extend(rs)
    return use


def listed():
    return rooms.load(rooms.ROOMS, {}).get("rooms", [])


def test_a_listing_from_the_app_reads_here():
    fields = rooms.read_listing(FROM_THE_APP)
    assert fields["room"] == "demo" and fields["code"] == "NDQE" and fields["note"] == "starting with the menus"
    signed = json.loads(rooms._unb64(FROM_THE_APP.split(":", 1)[1]))
    changed = "decomp.wtf-listing:" + b64(json.dumps({**signed, "code": "NDQP"}).encode())  # another region's game
    with pytest.raises(rooms.Refused, match="signed"):
        rooms.read_listing(changed)


def test_a_public_room_is_listed_with_what_it_says(lists):
    room = Room()
    lists(room)
    answer = rooms.handle(rooms.read_listing(room.listing()), NOW)
    assert answer.startswith("Listed.")
    (entry,) = listed()
    assert entry["key"] == room.key and entry["gist"] == room.gist and entry["url"] == ""
    assert (entry["members"], entry["matched"], entry["functions"], entry["approve"]) == (3, 30, 120, True)
    assert "title" not in entry and entry["note"] == "menus first"  # what the list shows: never the game's title


def test_only_the_rooms_key_lists_it(lists):
    room, other = Room(), Room()
    lists(room)
    forged = room.listing()
    fields = rooms.read_listing(forged)
    fields["note"] = "changed"  # after signing
    signed = {**fields, "sig": other.sign(rooms.listing_message(fields))}
    with pytest.raises(rooms.Refused, match="signed"):
        rooms.read_listing("decomp.wtf-listing:" + b64(json.dumps(signed).encode()))


def test_a_room_that_isnt_what_its_listing_says_isnt_listed(lists):
    room = Room()
    lists(room)
    with pytest.raises(rooms.Refused, match="sha1"):
        rooms.handle(rooms.read_listing(room.listing(sha1="b" * 40)), NOW)
    room.visibility = "private"
    with pytest.raises(rooms.Refused, match="isn't public"):
        rooms.handle(rooms.read_listing(room.listing(t=NOW + 1)), NOW)
    assert listed() == []


def test_a_room_somewhere_else_with_another_key_isnt_listed(lists):
    room, impostor = Room(), Room(url="https://abc-def.trycloudflare.com")
    lists(impostor)  # the address answers with another room's key
    impostor.gist = room.gist
    with pytest.raises(rooms.Refused):
        rooms.handle(rooms.read_listing(room.listing()), NOW)


def test_a_listing_counts_once(lists):
    room = Room()
    lists(room)
    first = room.listing(t=NOW - 100)
    rooms.handle(rooms.read_listing(first), NOW)
    rooms.handle(rooms.read_listing(room.listing("unlist", t=NOW - 50)), NOW)
    assert listed() == []
    with pytest.raises(rooms.Refused, match="used already"):  # the old listing, from its public issue, again
        rooms.handle(rooms.read_listing(first), NOW)
    with pytest.raises(rooms.Refused, match="too old"):
        rooms.handle(rooms.read_listing(room.listing(t=NOW - 8 * 86400)), NOW)


def test_a_blocked_room_isnt_listed(lists):
    room = Room()
    lists(room)
    rooms.save(rooms.BLOCKED, {"keys": [room.key]})
    with pytest.raises(rooms.Refused, match="can't be listed"):
        rooms.handle(rooms.read_listing(room.listing()), NOW)


def test_rooms_are_looked_at_again_and_taken_off_when_away_a_week(lists):
    here, away, gone_private = Room(), Room(url="https://away.trycloudflare.com", gist="1" * 20), \
        Room(url="https://private.trycloudflare.com", gist="2" * 20)
    lists(here, away, gone_private)
    for r in (here, away, gone_private):
        rooms.handle(rooms.read_listing(r.listing()), NOW)
    here.hello["matched"] = 45
    away.up = False
    gone_private.visibility = "private"
    rooms.check(NOW + 3600)
    by_key = {e["key"]: e for e in listed()}
    assert by_key[here.key]["matched"] == 45 and by_key[here.key]["seen"] == NOW + 3600
    assert by_key[away.key]["seen"] == NOW  # kept for now, as it was
    assert gone_private.key not in by_key  # it answered: not public any more
    here.note_expires = NOW + 9 * 86400  # its host keeps saying where it is
    rooms.check(NOW + 8 * 86400)
    assert [e["key"] for e in listed()] == [here.key]


def test_a_gist_note_that_expired_means_the_host_is_away(lists):
    room = Room()
    lists(room)
    room.note_expires = NOW - 1
    with pytest.raises(rooms.Refused, match="away"):
        rooms.handle(rooms.read_listing(room.listing()), NOW)


def test_only_public_addresses_are_asked():
    for url in ("http://127.0.0.1:6481", "http://192.168.1.20:6481", "http://169.254.169.254", "http://[::1]:6481",
                "http://10.0.0.5"):
        with pytest.raises(rooms.Refused, match="public internet"):
            rooms.public_address(url)
    with pytest.raises(rooms.Refused, match="web address"):
        rooms.public_address("file:///etc/passwd")


def test_an_issue_without_a_listing_is_answered():
    with pytest.raises(rooms.Refused, match="no listing"):
        rooms.read_listing("please list my room at http://example.org")


def test_the_issue_command_writes_an_answer(lists, tmp_path, monkeypatch):
    room = Room()
    lists(room)
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"issue": {"number": 7, "body": room.listing(t=int(time.time()))}}))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    room.note_expires = int(time.time()) + 86400
    assert rooms.main(["rooms.py", "issue"]) == 0
    reply = rooms.load(rooms.REPLY, None)
    assert reply["issue"] == 7 and reply["ok"] and reply["answer"].startswith("Listed.")
