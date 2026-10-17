"""The room list's keeper, run by this repository's Action.

    python tools/rooms.py issue   an issue was opened: list or unlist the room its listing names (writes reply.json)
    python tools/rooms.py reply   answer that issue, once the list is pushed
    python tools/rooms.py check   look at every listed room again; take off the ones away for a week

A listing is what decomp.wtf writes for a public room its host wants on the list ("decomp.wtf-listing:" and base64):
its fields, signed with the room's own key (Ed25519). The room proves it holds that key whenever asked
(/collab/ping), and a room on a quick tunnel says where it is now in its host's gist, signed with the same key: so
nobody can list, unlist or misplace a room but its host. Each listed room is checked: it answers with its key, it's
public, and its game (sha1), product code, platform and kind are what the listing says. rooms.json is what
decomp.wtf's Open rooms page reads; ledger.json remembers each room's latest listing, so an old one (issues are
public) can't be used again.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import re
import secrets
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
ROOMS, LEDGER, BLOCKED, REPLY = (ROOT / n for n in ("rooms.json", "ledger.json", "blocked.json", "reply.json"))
GITHUB = "https://api.github.com"
NOTE = "decomp-wtf-room.json"  # the file in a host's gist (decomp.wtf's identity.py)
LISTING = re.compile(r"decomp\.wtf-listing:([A-Za-z0-9_-]{40,4000})")
AWAY = 7 * 86400  # a room that doesn't answer for this long comes off the list
MAX_AGE = 7 * 86400  # how old a listing may be when it's submitted
MAX_BODY = 1 << 20

FIELDS = {  # what a listing holds (decomp.wtf's roomlist.py), and how each must look
    "action": re.compile(r"^(list|unlist)$"), "key": re.compile(r"^[A-Za-z0-9_-]{43}$"), "room": re.compile(r"^[\w-]{1,64}$"),
    "gist": re.compile(r"^([0-9a-f]{20,40})?$"), "url": re.compile(r"^(https?://[^\s/?#]{1,200})?$"),
    "platform": re.compile(r"^[a-z0-9]{1,12}$"), "sha1": re.compile(r"^([0-9a-f]{40})?$"),
    "code": re.compile(r"^[\w.-]{0,32}$"), "kind": re.compile(r"^(rom|fork|scratch)$"),
    "repo": re.compile(r"^(https://[^\s]{1,200})?$"),
}
QUICK_TUNNEL = re.compile(r"^https://[a-z0-9-]+\.trycloudflare\.com$")


class Refused(Exception):
    """Why a room can't be (or stay) on the list. `final`: it answered, and it isn't what it was listed as."""

    def __init__(self, why: str, final: bool = False):
        super().__init__(why)
        self.final = final


# ------------------------------------------------------------------------------------------------ signatures

def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def verify(key: str, message: str, signature: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(key)).verify(_unb64(signature), message.encode())
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def listing_message(fields: dict) -> str:
    return "decomp.wtf room listing v1\n" + json.dumps(fields, sort_keys=True, separators=(",", ":"))


def ping_message(url: str, room: str, nonce: str) -> str:
    return f"decomp.wtf room ping v1\n{url}\n{room}\n{nonce}"


def pointer_message(key: str, url: str, t: int, expires: int) -> str:
    return f"decomp.wtf room pointer v1\n{key}\n{url}\n{t}\n{expires}"


def read_listing(text: str) -> dict:
    """The listing in an issue's text, checked: its fields, and its signature by the room's key."""
    m = LISTING.search(text or "")
    if not m:
        raise Refused("there's no listing in this issue: decomp.wtf writes one in the room's Team tab (List it)")
    try:
        got = json.loads(_unb64(m.group(1)))
    except (ValueError, binascii.Error):
        raise Refused("the listing is cut short or changed: copy it again from decomp.wtf") from None
    if not isinstance(got, dict) or not isinstance(got.get("sig"), str) or not isinstance(got.get("t"), int):
        raise Refused("that isn't a listing decomp.wtf wrote")
    fields = {k: v for k, v in got.items() if k != "sig"}
    wanted = ("action", "key", "room") if fields.get("action") == "unlist" else tuple(FIELDS)
    for name in wanted:
        if not isinstance(fields.get(name), str) or not FIELDS[name].match(fields[name]):
            raise Refused(f"the listing's {name} doesn't look right")
    if fields["action"] == "list":
        if not isinstance(fields.get("note", ""), str) or len(fields.get("note", "")) > 200:
            raise Refused("the listing's note is too long")
        if not (fields["gist"] or fields["url"]):
            raise Refused("the listing doesn't say where to find the room")
    if not verify(fields["key"], listing_message(fields), got["sig"]):
        raise Refused("the listing isn't signed with the room's key: copy it again from decomp.wtf")
    return fields


# ------------------------------------------------------------------------------------------------ the network

def public_address(url: str) -> None:
    """Refuse an address that isn't on the public internet (the Action runs on GitHub's machines: nothing of
    theirs, nor anyone's private network, is to be asked)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise Refused("the room's address isn't a web address")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
    except (socket.gaierror, UnicodeError):
        raise Refused(f"{parts.hostname} doesn't resolve") from None
    for info in infos:
        if not ipaddress.ip_address(info[4][0]).is_global:
            raise Refused("the room's address isn't on the public internet (a LAN or Tailscale address can't be listed)",
                          final=True)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a redirect would lead past public_address's check
        return None


_open = urllib.request.build_opener(_NoRedirects).open


def fetch(url: str, headers: dict | None = None, timeout: float = 20) -> tuple[int, dict]:
    """GET a JSON answer, following no redirect: (status, body or {})."""
    req = urllib.request.Request(url, headers={"user-agent": "decomp.wtf-rooms", **(headers or {})})
    try:
        with _open(req, timeout=timeout) as r:
            raw = r.read(MAX_BODY + 1)
            status = r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(MAX_BODY + 1), e.code
    except (urllib.error.URLError, OSError, ValueError):
        return 0, {}
    try:
        body = json.loads(raw[:MAX_BODY]) if len(raw) <= MAX_BODY else {}
    except ValueError:
        body = {}
    return status, body if isinstance(body, dict) else {}


def github(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(f"{GITHUB}{path}", method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
                                          "accept": "application/vnd.github+json", "user-agent": "decomp.wtf-rooms"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"{}")


def where(entry: dict, now: float) -> str:
    """Where a listed room is now: its own address, or what its host's gist says (signed by the room)."""
    if entry.get("url"):
        return entry["url"]
    token = os.environ.get("GITHUB_TOKEN")
    status, gist = fetch(f"{GITHUB}/gists/{entry['gist']}", {"accept": "application/vnd.github+json",
                                                              **({"authorization": f"Bearer {token}"} if token else {})})
    if status == 404:
        raise Refused("the room's gist is gone")
    try:
        note = json.loads(gist["files"][NOTE]["content"])
        url, t, expires, sig = str(note["url"]), int(note["t"]), int(note["expires"]), str(note["sig"])
    except (KeyError, TypeError, ValueError):
        raise Refused("the room's gist doesn't say where it is (is its host's decomp.wtf running?)") from None
    if not verify(entry["key"], pointer_message(entry["key"], url, t, expires), sig) or not QUICK_TUNNEL.match(url):
        raise Refused("the room's gist isn't signed with its key", final=True)
    if expires < now:
        raise Refused("the room hasn't said where it is lately: its host is away")
    return url


def probe(entry: dict, now: float | None = None) -> dict:
    """Check a listed room where it is now: it shows its key, it's public, and it's the game the listing says.
    Returns what the list shows of it (members, progress)."""
    now = time.time() if now is None else now
    url = where(entry, now).rstrip("/")
    public_address(url)
    nonce = secrets.token_urlsafe(18)
    q = urllib.parse.urlencode({"room": entry["room"], "nonce": nonce})
    status, ping = fetch(f"{url}/collab/ping?{q}")
    if status == 0:
        raise Refused("the room doesn't answer: is its host's decomp.wtf open and sharing it?")
    if status != 200 or ping.get("key") != entry["key"] or \
            not verify(entry["key"], ping_message(url, entry["room"], nonce), str(ping.get("signature") or "")):
        raise Refused("the room at that address doesn't show the listed room's key", final=True)
    status, hello = fetch(f"{url}/collab/hello?{urllib.parse.urlencode({'room': entry['room'], 'invite': 'open'})}")
    if status != 200 or hello.get("visibility") != "public":
        raise Refused("the room isn't public: only rooms anyone with the address can join are listed", final=True)
    kind = "rom" if hello.get("kind") == "rom" else "scratch" if hello.get("origin") == "scratch" else "fork"
    said = {"sha1": hello.get("sha1") or "", "code": hello.get("game_code") or "", "platform": hello.get("platform") or "",
            "kind": kind, "repo": (hello.get("repo_url") or "") if kind == "fork" else ""}
    for name, value in said.items():
        if entry.get(name, "") != value:
            raise Refused(f"the room's {name} isn't what the listing says", final=True)
    number = lambda v: v if isinstance(v, int) and v >= 0 else 0  # noqa: E731
    return {"functions": number(hello.get("functions")), "matched": number(hello.get("matched")),
            "members": number(hello.get("members")), "limit": number(hello.get("limit")),
            "approve": hello.get("approve") is True}


# ------------------------------------------------------------------------------------------------ the list

def load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def save_rooms(rooms: list[dict], now: float) -> None:
    rooms = sorted(rooms, key=lambda r: (-r.get("seen", 0), r["key"]))
    save(ROOMS, {"version": 1, "updated": int(now), "rooms": rooms})


def handle(fields: dict, now: float) -> str:
    """List or unlist the room a checked listing names; returns the answer for the issue."""
    rooms = load(ROOMS, {}).get("rooms", [])
    ledger = load(LEDGER, {})
    blocked = set(load(BLOCKED, {}).get("keys", []))
    key = fields["key"]
    if key in blocked:
        raise Refused("this room can't be listed here")
    if not now - MAX_AGE <= fields["t"] <= now + 600:
        raise Refused("the listing is too old: make a new one in decomp.wtf (Team tab)")
    if fields["t"] <= ledger.get(key, 0):
        raise Refused("this listing was used already: make a new one in decomp.wtf (Team tab)")
    rest = [r for r in rooms if r["key"] != key]
    if fields["action"] == "unlist":
        ledger[key] = fields["t"]
        save(LEDGER, ledger)
        save_rooms(rest, now)
        return "Taken off the list. ✓" if len(rest) < len(rooms) else "It wasn't on the list. ✓"
    stats = probe(fields, now)
    entry = {k: fields.get(k, "") for k in ("key", "room", "gist", "url", "platform", "sha1", "code", "kind", "repo")}
    entry |= {"note": " ".join(str(fields.get("note") or "").split())[:200], "seen": int(now),
              "listed": next((r["listed"] for r in rooms if r["key"] == key), int(now)), **stats}
    ledger[key] = fields["t"]
    save(LEDGER, ledger)
    save_rooms(rest + [entry], now)
    return (f"Listed. ✓ It's in decomp.wtf's **Open rooms** now ({stats['members']} members, "
            f"{stats['matched']} of {stats['functions']} functions matched). The list looks at it again every few hours "
            "and takes it off when it stays away for a week.")


def check(now: float | None = None) -> None:
    """Look at every listed room again."""
    now = time.time() if now is None else now
    rooms = load(ROOMS, {}).get("rooms", [])

    def again(entry: dict) -> dict | None:
        try:
            return entry | probe(entry, now) | {"seen": int(now)}
        except Refused as e:
            return None if e.final or now - entry.get("seen", 0) > AWAY else entry

    with ThreadPoolExecutor(8) as pool:
        kept = [e for e in pool.map(again, rooms) if e is not None]
    save_rooms(kept, now)


def main(argv: list[str]) -> int:
    command = argv[1] if len(argv) > 1 else ""
    if command == "check":
        check()
        return 0
    if command == "issue":
        issue = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))["issue"]
        try:
            answer, ok = handle(read_listing(issue.get("body") or ""), time.time()), True
        except Refused as e:
            answer, ok = f"Not listed: {e}.", False
        save(REPLY, {"issue": issue["number"], "answer": answer, "ok": ok})
        return 0
    if command == "reply":
        reply = load(REPLY, None)
        if reply:
            github("POST", f"/repos/{os.environ['GITHUB_REPOSITORY']}/issues/{reply['issue']}/comments", {"body": reply["answer"]})
            github("PATCH", f"/repos/{os.environ['GITHUB_REPOSITORY']}/issues/{reply['issue']}",
                   {"state": "closed", "state_reason": "completed" if reply["ok"] else "not_planned"})
            REPLY.unlink()
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
