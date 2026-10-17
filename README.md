# decomp.wtf rooms

The public list of [decomp.wtf](https://github.com/SynapticDreams/decomp.wtf) rooms that anyone with their own copy
of the game can join. decomp.wtf's **Open rooms** page reads [`rooms.json`](rooms.json).

## Listing a room

In decomp.wtf, open the room's **Team** tab and make it public. Then choose **List it**. decomp.wtf writes a listing
signed with the room's own key and opens an issue form here, filled in with it. Submit the issue (you need to be
signed in to GitHub). Within a few minutes the list:

1. checks the signature: only the room's host can list it, or take it off;
2. finds the room: at its own address, or for a room shared through a quick tunnel, where its host's gist says it
   is now (decomp.wtf keeps that up to date when you connect GitHub in the Team tab);
3. checks that the room answers there with its key, is public, and is the game the listing says (by the game's
   checksum, product code and platform);
4. adds it to `rooms.json` and answers the issue.

**Take it off the list** in the same tab works the same way. Every six hours the list looks at each room again
(members, progress). A room that has been away for a week, or that stopped being public, comes off by itself.

## What the list shows

For each room: its key and name, where to find it (the host's gist, or the room's own address), its platform,
product code, the game's checksum (so decomp.wtf can tell you have the game) and kind (from the game itself, a fork
of a public decomp, or started from scratch). Then the host's note, how many members it has and how much is
matched. It never holds a game's title. decomp.wtf shows the title for a game you have.

**What becomes public:** your issue, under your GitHub account, and, for a quick-tunnel room, your gist, which
shows which account it's on. Nothing of the game, its code or the room's work is ever here.

## The rules

Everyone in a listed room uses their own, legally obtained copy of the game. decomp.wtf checks each copy, never
sends game files, and keeps what the room makes with people who own the game. Joining a room started from scratch
means trusting its host, because building its project runs the host's build setup; decomp.wtf asks before doing it.

To report a room, open an ordinary issue. Rooms the maintainers take off are kept out by their key in
[`blocked.json`](blocked.json).

## How it works

- `tools/rooms.py`: everything the Action does: reading listings, checking rooms, keeping the files.
- `.github/workflows/rooms.yml`: runs it when an issue is opened, every six hours, and by hand.
- `ledger.json`: each room's latest listing. Issues are public, so an old listing can't be used again.
- `tests/`: `python -m pytest` (needs `cryptography`).

The listing format and signatures are decomp.wtf's `roomlist.py` and `identity.py`.
