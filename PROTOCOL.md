# DF CONNECTED v2.7.15 — Network Protocol Reference

Wire protocol of the shipped Windows build: `DONTFORGET.exe` (YoYo Compiler output) and its networking extension
`Dll.dll`. Layouts were read from the binaries and checked against a capture, `game.pcapng` (connect → login → join
session → stand in the hub → send "hi"). In that capture, 205 client and 7,992 server frames deframe exactly to the end
of both TCP streams, and every gameplay message parses with zero leftover bytes under the layouts below.
A second capture, `game2.pcapng` (account `user_b`: connect → login → spawn → walk → warp to the hub → global chat
→ local chat → open another user's profile → join a guild; 60 s), was decoded with the Wireshark dissector
`protocol-test/wireshark/dfc.lua`: 385 client and 10,606 server messages, all parsed with zero leftover bytes.
Player names in the examples are anonymized (`user_a` … `user_e`, each 6 characters like the originals, so length
bytes stay correct), and player IDs and the IDs derived from them are replaced with made-up values that keep the
same arithmetic.

**✔ capture** marks items seen byte-for-byte in a capture (**✔ game2** when only in the second one); everything else is from code, and **(inferred)** marks
items reasoned rather than read directly. The login-hash and `0x91`-token payloads and the handshake hardware
fingerprints are described at the framing level only. `FUN_XXXXXXXX` names are addresses in `Dll.dll` (image base
`0x10000000`).

## Table of contents

1. [Architecture](#1-architecture)
2. [Transport](#2-transport)
3. [Framing](#3-framing)
   - [3.1 Length prefix](#31-length-prefix-all-messages-except-the-handshake) · [3.2 Handshake exception](#32-handshake-exception)
4. [Primitive encodings](#4-primitive-encodings)
   - [4.1 Typed value (`TValue`)](#41-typed-value-tvalue--used-for-variables-and-p2p-arguments) · [4.2 Named-variable record (`NVar`) and name caches](#42-named-variable-record-nvar-and-name-caches)
5. [Session lifecycle](#5-session-lifecycle)
   - [5.1 Handshake](#51-0x01-handshake-cs--fun_1003baf0-u16-framed-574-b-) · [5.2 Login](#52-0x02-login-cs--fun_1003c500-) · [5.3 Login result](#53-0x02-login-result-sc) · [5.4 `0x9B` auth-token exchange](#54-0x9b-authentication-token-exchange-required-for-login-) · [5.5 Resource enumeration and manifest](#55-resource-enumeration-0x14--manifest-0x15)
6. [Client → Server message catalogue](#6-client--server-message-catalogue)
7. [Movement (walking around)](#7-movement-walking-around)
   - [7.1 What the game syncs](#71-what-the-game-syncs) · [7.2 Send policy](#72-send-policy-dead-reckoning) · [7.3 Wire format](#73-wire-format)
8. [Player variables](#8-player-variables-the-interact-with-the-world-state)
9. [Chat](#9-chat)
   - [9.1 Global / local chat](#91-global--local-chat-server-relayed) · [9.2 DMs and guild chat](#92-direct-messages-and-guild-chat-p2p) · [9.3 Slash commands](#93-slash-commands-client-side-scr_commands)
10. [Synced instances](#10-synced-instances-projectiles-chat-history-objects)
11. [P2P messages](#11-p2p-messages-game-level-protocol)
    - [11.1 Wire](#111-wire) · [11.2 Message catalogue](#112-message-catalogue)
12. [Server → Client message catalogue](#12-server--client-message-catalogue)
    - [12.1 GML action IDs](#121-gml-action-ids-what-the-game-does-with-each-sc-message)
13. [Anti-cheat / telemetry notes](#13-anti-cheat--telemetry-notes)
    - [13.1 Module scan and the `0x98` query](#131-module-scan-and-the-0x98-query)
14. [Verification status and open questions](#14-verification-status-and-open-questions)
    - [Key addresses (`Dll.dll`)](#key-addresses-dlldll-image-base-0x10000000) · [Key functions (`DONTFORGET.exe`)](#key-functions-dontforgetexe-yyc)

---

## 1. Architecture

The game does **not** implement its own socket code in GML. Multiplayer is built on the third-party
**GameMaker Server+ (GMS)** extension ("XServer"):

| Layer | Where it lives | What it does |
|---|---|---|
| Game logic | `DONTFORGET.exe` (YYC-compiled GML; `gml_Object_*` / `gml_Script_*`) | Decides *what* to sync: player variables, P2P messages, chat, synced instances. |
| GMS GML wrappers | same exe (`gml_Script_gms_*`, `gml_Script_XServer_*`) | Thin GML API (`gms_self_set`, `gms_p2p_send`, `gms_chat`, `gms_step`, …). |
| GMS native client | `Dll.dll` (extension *"GameMaker Server+(Windows)"*, 199 exported functions) | TCP connection, framing, encoding, caches, dead-reckoning, login, anti-tamper. |
| Server | `N.gamehost.gamemakerserver.com:25500` | Third-party hosted relay/persistence server (not part of this install). |

Other extensions in the build (not network-relevant): `rousrDissonance.dll` (Discord Rich Presence), `expr.dll`,
`execute_shell_simple.dll`.

The game registers itself with **`gms_init(1322)`** (GMS game ID; the gamemakerserver.com web listing is game `4113`).

---

## 2. Transport

| Property | Value | Evidence |
|---|---|---|
| Protocol | TCP (IPv4), non-blocking, `TCP_NODELAY` enabled | `Dll.dll` `FUN_10037b10` |
| Port | **25500** (`htons(0x639C)`) | `FUN_10037b10` |
| Host | One of `0.gamehost.gamemakerserver.com` … `9.gamehost.gamemakerserver.com`, picked at random (`rand() % 10`, seeded with `time()`). Capture: `135.125.190.8:25500` ✔ | `FUN_10039140` |
| Host override | If `alternate-host.txt` exists in the working dir, its contents (≤1023 bytes) are used as the hostname. A cached host from settings also takes priority if present. | `FUN_10039140` |
| Connect timeout | 5 s (`select`) | `FUN_10037b10` |
| Idle timeout | Client disconnects if **no bytes received for 30 s** | `FUN_10030330` |
| Encryption / compression | **None.** Payloads are plain binary. (Passwords are hashed — see §5.2.) | |
| Endianness | All multi-byte integers and floats are **little-endian**. | |

Everything is driven by the game calling `gms_step()` once per frame. `gms_step` → `Step()` in the DLL, which
(a) queues outgoing messages into one buffer and `send()`s it once per frame, and (b) `recv()`s up to 64 KiB and
dispatches every complete frame.

---

## 3. Framing

Every message is `[length][payload]`, where `payload[0]` is the **message ID** byte.

### 3.1 Length prefix (all messages except the handshake)

A little-endian base-128 varint whose **continuation flag is bit 0** (not bit 7):

```
each byte = (7 bits of length << 1) | more
more = 1 → another length byte follows
```

| Payload length | Bytes | Encoding |
|---|---|---|
| < 0x80 | 1 | `len << 1` |
| < 0x4000 | 2 | `(len << 1) \| 1`, `((len >> 7) << 1)` |
| < 0x200000 | 3 | `(len<<1)\|1`, `((len>>7)<<1)\|1`, `(len>>14)<<1` |

Decoder: `len = Σ (byte_i >> 1) << (7·i)` until a byte with bit 0 = 0. (A 4th byte exists in the code, but the encoder
and decoder disagree on it, so frames ≥ 2 MiB are effectively unsupported.)

Source: encoder `FUN_100385b0`, decoder `FUN_10030330`.

### 3.2 Handshake exception

The very first client message (ID `0x01`, §5.1) is framed with a plain **`u16` little-endian length** instead of the
varint (`FUN_100387a0`). Everything after it uses the varint. ✔ capture (`3e 02 01 …` = 574-byte handshake). The
server never uses the u16 form.

Many messages are usually packed into one TCP segment (one `send()` per game frame), and a message may span segments.

---

## 4. Primitive encodings

| Name | Encoding |
|---|---|
| `u8` / `u16` / `u32` / `i32` | little-endian integers |
| `f32` / `f64` | IEEE-754 little-endian |
| `u64 playerID` | 8 bytes; GMS player IDs are 64-bit |
| `str` | `u16 length` + raw bytes (no terminator) — `FUN_1003a3c0` / `FUN_1003a5f0` |

### 4.1 Typed value (`TValue`) — used for variables and P2P arguments

One **type byte** followed by a payload (`FUN_1003a930` write, `FUN_10025d90` read):

| Type byte | Meaning | Payload |
|---|---|---|
| `1xxxxxxx` (`0x80`–`0xFF`) | small integer: `value = (t & 0x7F) − 64` (range −64…63) | none |
| `0111 1111` (`0x7F`) | f64 | 8 bytes |
| `0x7E` | f32 | 4 bytes |
| `0x7D` | string | `u16 len` + bytes |
| `0x7C` | string | `u8 len` + bytes |
| `0x78`–`0x7B` | short string of length `t & 7` (0–3) | that many bytes |
| `0eeee nn s` (other `0x00`–`0x77`) | fixed-point number | `n+1` bytes, little-endian unsigned mantissa `m` |

Fixed-point decode: `e = (t>>3)&0xF` (0–14), `n = (t>>1)&3`, `s = t&1`

```
D     = {1, 2, 5}[e % 3] · 10^(e / 3)      // 1, 2, 5, 10, 20, 50, 100, …
value = (s ? −1 : +1) · m / D
```

The encoder (`FUN_1003abc0`) picks the smallest `(bytes, D)` that represents the value within the variable's
precision (`gms_self_set_precision`; default `1e-5`). So `x = 123.5` goes out as 2 bytes with `D = 2`.

✔ capture examples: `image_alpha` fading in sends type `0x20` (1 byte, D=20) for 0.15, `0x18` (D=10) for 0.3,
`0x10` (D=5) for 0.4; `myhp = 20` uses `0xD4` (small int); `myname` uses `0x7C` (u8-length string);
`sprite_index = 2368` uses `0x02` (2 bytes, D=1); an empty string is `0x78`.

### 4.2 Named-variable record (`NVar`) and name caches

Used for player variables, global variables, INI entries and synced-instance variables
(`FUN_1003af60` write / `FUN_10026060` read):

```
u8 slot
slot == 0 : str name, str value          (uncached string)
slot == 1 : str name, f64 value          (uncached real)
slot >= 2 : <TValue payload WITHOUT the type byte>   — name and type come from the cache slot
```

Both sides keep LRU **name caches** (separate tables per variable family). Before a slot is used, the sender
defines it (in the same frame batch, immediately before first use):

```
0x85 + cacheTable : u8 slot, str name, u8 typeByte          (both directions; IDs 0x85–0x8A)
```

| ID | Table | Status |
|---|---|---|
| `0x85` | player variables (`0x03`) | ✔ capture, both directions |
| `0x86` | global variables (`0x06`) | inferred |
| `0x87` | PlayerINI (`0x0C`) | ✔ capture (S→C) |
| `0x88` | GameINI (`0x0E`) | ✔ capture (S→C) |
| `0x89`, `0x8A` | other families (instance vars / data updates) | inferred |

Cache facts from the capture:
- A cache entry is keyed by **(name, type byte)**, not just name. The same variable can occupy several slots at once
  (e.g. `pf_message1` with types `0x7B` and `0x7C`), and a value whose encoding changes needs a new slot
  (`image_alpha` got slots `0xFE`, `0xFD`, `0xFC` as its precision changed).
- Slots are chosen by the sender: the client allocates its player-variable slots **downward from `0xFF`**; the server
  does the same for player variables and allocates INI slots **upward from `0x02`**.
- The first time a value is sent it often goes out uncached (slot `0`/`1`), and later updates use the cached slot.

The **player cache** maps a 1-byte index to a 64-bit player ID, so later messages can name a player with one byte:

```
0x8C : u8 index, u64 playerID                              (both directions)
```

Every server message below that carries `u8 player` refers to this index. The server hands out indices upward from
`0` in the order it first mentions players; **your own player has no fixed index**. ✔ capture: in `game.pcapng` you
were alone in your first session, so index `0` was you; in `game2.pcapng` index `0` was another player (`user_c`) in
the pre-join session, and your own ID (from `0x18`) only got an index (`41`) when the server relayed your own P2P
broadcast back to you. Use S→C `0x18` to learn your own ID. The client defines its own indices separately, downward
from `0xFF`; P2P broadcast uses client index **`0xFF` mapped to player ID `0`** (✔ both captures: `8c ff <u64 0>`, §11).

---

## 5. Session lifecycle

Observed order (✔ capture, `game.pcapng`, times relative to the first client packet):

The S→C order below is identical in both captures, message for message, up to the login result.

```
C→S  0x01 handshake (u16-framed, 574 B), 0x96 env report, 0x41 version(2487.0), 0x8F sending-policy(1,1),
     0x03 room
S→C  0x2A ×10 highscore-list titles, then per list: 0x2C clear + 0x2B ×500 entries (10 lists, ~110 KB),
     0x38 server clock, 0x84 geo, 0x01 connection-confirmed,
     0x14 ×5 resource-enumeration requests (kinds 0–4, §5.5), 0x9B challenge,
     0x0E ×32 GameINI values (uncached, slots 0/1), 0x42 no-update
C→S  0x9B challenge response, 0x15 resource manifest (zlib, 38 KB, split across many segments)
     (pings 0x64 / acks continue throughout)
C→S  0x02 login  (type 1; "user_a" / "user_b")
S→C  0x83 username, 0x8C + 0x05 players already in your first session (and their 0x03 vars / 0xE9 positions),
     0x35 master, 0x19 sync-ID base, 0x5E session list, 0x07 ×10 team scores,
     0x0C PlayerINI dump (with 0x87 cache defs; 26 values for user_a, 1,524 for user_b: it is the account's save),
     0x18 own player ID, 0x2E friend entries, 0x31 own admin rights, 0x5E, 0x23 limits,
     **0x02 login OK** (it arrives *after* the account data), 0x91 auth token,
     0x0E GameINI values (with 0x88 defs), 0x5E, 0x5C current session (a small session: 803 / 958)
C→S  0x03 player vars, own movement, 0x4B BDB open (own profile, §6), more 0x03 vars
C→S  0x5D join session 3 (the game sent it twice in game2), 0x85/0x03 vars, own movement,
     0x8C self player-cache (idx 0xFF → id 0), 0x16 P2P-22 (friend-online broadcast)
S→C  0x05 status 1 for players of the old session, then the new roster as 0x8C + 0x05 status 0 + name
     (37 / 40 players) with their 0x03 vars and 0xE9 positions, 0x5E, 0x5C current session 3,
     0x16 your own P2P-22 relayed back to you
     steady state: 0x0A chat relays from others (tag "localchat"), 0x03 var changes, movement
```

Throughout the steady state the client sends a bare `0x97` keep-alive (~every 10 frames, ≈3/s) and acks each
server `0x64` ping; the server sends `0x64 <b>` about **once per second** (mean interval 1.01 s in both captures),
where `b` carries the server-measured round-trip time (`ping = 3·b` ms, see §12). `game.pcapng` ran ~20 s,
`game2.pcapng` ~45 s of game traffic.

### 5.1 `0x01` Handshake (C→S) — `FUN_1003baf0`, u16-framed, 574 B ✔

| Field | Type | Captured value |
|---|---|---|
| id | u8 | `0x01` |
| GMS+ client version | f64 | `2.55` |
| — | u8 | `0` |
| app identifier | f64 | `291866908.0` (fixed constant, not the `gms_init` value) |
| magic | 4 × f64 | `1038746284749.0`, `9847837487487.0`, `3183648256511.0`, `6178346799275.0` |
| env flags | u32 | `0x400` in `game.pcapng`, `0` in `game2.pcapng` (debugger / VM / sandbox / suspicious-tool bitmask — `FUN_1000ee20`; see §13). With `0`, the `0x96` report carries no module list. |
| hw id 1–4 | 4 × str | hardware fingerprints (WMI `Win32_BaseBoard`/`Win32_BIOS` serials, model, `GetSystemInfo`) — `FUN_1000f050` |

### 5.2 `0x02` Login (C→S) — `FUN_1003c500` ✔

```
u8  0x02
u8  loginType          0 = username only (guest), 1 = username + password, 2 = username + login token
str username                                                         (capture: "user_a")
type 1:  str hash1 = hex(SHA-512(password + SALT1))                  (128 lowercase hex chars) ✔
         u8  strlen(password)                                        (capture: 8)
         str hash2 = hex(SHA-512(password + username + SALT2))       (128 hex chars) ✔
type 2:  str token
```

`SALT1` = `0SSFE, but IT changes (it only becomes longer): '4004583eb8fb7f89!'`
`SALT2` = `Y8d0cdofKW9J0ZxmfqE06VaelEQN8+CGaJ6sSJZEKmDVbQHJlAETkeQZtp6QjlWHJWrqu+CHkj4z14Sfh1FN2hKz1O0kUsdoNTrgMsPZHqCQ1kJFaxuowlPbjTuYzL8p6SIvhU/2Piy6RUrsjDnwgefmbQraodqi/`

### 5.3 `0x02` Login result (S→C)

`u8 status`, then by category: **error** → `u8 errorCode, str message`; **success** → nothing;
**success + token** → `str loginToken`.

**Success is `status == 1` specifically — not merely "non-zero".** This is authoritative: the DLL stores the
status byte in a global and its `isLoggedIn()` export returns `connected && (status == 1)` (`loginError()` returns
the separate `errorCode`). The capture's successful login was `02 01` (status 1, no trailing bytes). Any other
status value means *not logged in*; a session list (`0x5E`) can still arrive, so receiving one does **not** prove
login succeeded — check `status == 1`.

`errorCode` values (from the game's `gms_login_error_tostring`):

| Code | Meaning |
|---|---|
| 0 | Server not responding to login request |
| 1 | A password is required for this account |
| 2 | Account does not exist (register first) |
| 3 | Wrong password |
| 4 | Server full |
| 5 | Can't log in twice with the same name |
| 6 | Already logged in |
| 7 | Banned from this game |
| 8 | Banned from GameMaker Server |
| 11 | Username contains invalid characters |
| 12 | Username already used in the highscores |
| 13 | Could not connect to server |
| 15 | **Client unauthenticated** — the `0x9B` anti-tamper check (§5.4) failed or was not answered |

### 5.4 `0x9B` authentication-token exchange (required for login) ✔

An anti-tamper challenge–response handled inside the S→C dispatcher (`Dll.dll FUN_1002c100`), and it **gates
login**. Flow:

1. During the pre-login phase the server sends `0x9B str challenge` — a **128-char base64** string. ✔ capture.
2. The client replies `0x9B str response` where **`response = hex(SHA-512(challenge ∥ secret))`** — lowercase,
   128 hex chars. ✔ capture. The real client answers **before** sending `0x02`; an unanswered `0x9B` makes the
   server reject login with **error 15, "client unauthenticated"** (observed live).

**The secret (per-game constant):**

```
650e4bd11b8c1d76e0e9e997dae172c8e9bd0400
```

A 40-character lowercase-hex ASCII string (hashed as its 40 text bytes, *not* decoded to 20 raw bytes).

**Where the secret comes from.** The game EXE assembles it in compiled GML and hands it to the DLL **once**, during
GMS init (the GMS controller's Create event), through the extension export `gms_settings_set_game_secret`
(`Dll.dll` export #77, `FUN_10004710`). The DLL copies it into a global MSVC `std::string` at image offset
`0x1b2b38` (`DAT_101b2b38`). It is **not** a plaintext literal in either binary: `DONTFORGET.exe` contains only the
export's name, and the value is built at runtime. Hooking the export at process start and reading its argument yields
the value above.

**How the DLL builds the response.** On each `0x9B` challenge, `FUN_1002c100`:
- reads the challenge string;
- builds `challenge ∥ secret` via `FUN_1001e920(dest, challenge, secret)` — challenge first, then the secret from
  `DAT_101b2b38` appended (this fixes the concatenation order);
- hashes it with **CryptoPP SHA-512** and hex-encodes the 64-byte digest through a `"0123456789abcdef"` table (the
  same hashing shape as the login hashes in `FUN_1003c500`);
- sends it back through the `0x9B` writer `FUN_1003d6e0` as `0x9B str response`.

**Verified against `game.pcapng` (byte-for-byte).** With the recovered secret, `SHA-512(challenge ∥ secret)`
reproduces the captured client response exactly:

```
challenge = bZkss3V+iA5pjW+Kli2+GDo47OX9jndDNckRFMpNCBmEp0Ku+mClksIHcI4wSAMGug1cRTujgTLaWLZSfyjVlxrX/5Z+vcGUHS9rYFWwiKnFH7lyqAizrTQeX4SQKI0M
secret    = 650e4bd11b8c1d76e0e9e997dae172c8e9bd0400
response  = sha512(challenge + secret)
          = 66177df80db12310b7ead8d969e712d8e93f337faa0062eb7d6f0ceced21a6833b60007c08424217a3a64e5524801266f5acf0646f81faa92bff1709fddf6a5d   ← equals the captured client 0x9B ✔
```

The server verifies the hash value. Reference implementation:
`sha512_hex(challenge_ascii_bytes + b"650e4bd11b8c1d76e0e9e997dae172c8e9bd0400")`.

Also seen: server `0x91 str authToken` (base64, 128 chars), a post-login token. The DLL does not keep or check it. It hands the string to the game as GML action 51, which calls the script registered with
`gms_script_set_authentication_token_received`. Its contents are otherwise described at the framing level only.

### 5.5 Resource enumeration (`0x14`) → manifest (`0x15`)

The five `0x14` messages the server sends before login are **resource-enumeration requests**, not generic callbacks.
Each one is `0x14 u8 kind`. The DLL turns it into GML action 6 with `kind` in the sender slot, and `gms_step`
switches on `kind`:

| kind | GML loop in `gms_step` |
|---|---|
| 0 | every sound: `sound_exists` / `sound_get_name` → `XServer_set_resource` |
| 1 | every object: `object_exists` / `object_get_name` → `XServer_set_resource` |
| 2 | every room: `room_exists` / `room_get_name` → `XServer_set_resource` |
| 3 | every script: `script_exists` / `script_get_name` → `XServer_set_resource` |
| 4 | every sprite: name plus `sprite_get_width/height/xoffset/yoffset/bbox_*` → `XServer_set_resource_spritename` |

The names collected this way make up the zlib-compressed **`0x15` resource manifest** the client uploads right
afterwards. The server can then refer to resources by index, for example in `0x15` sound commands and `0x50`
`room_goto` (§12). The capture shows exactly this order: `0x14` kinds 0–4, then the C→S `0x15`.

---

## 6. Client → Server message catalogue

| ID | Name | Payload | Source |
|---|---|---|---|
| `0x01` | Handshake | §5.1 | `FUN_1003baf0` |
| `0x02` | Login | §5.2 | `FUN_1003c500` |
| `0x03` | Set own player variable | `NVar` | `FUN_1003cdb0` |
| `0x06` | Set global variable | `NVar` | `Step` |
| `0x07` | **Team score set** | `u8 team (clamped 0–10), f32 score` | `teamSetScore` → `FUN_1003fb70` |
| `0x08` / `0x1A` / `0x1B` / `0x1C` / `0x1D` / `0x1E` | Create synced instance | §10 | `FUN_1003e200` |
| `0x09` | Destroy synced instance | `u16 syncID−1000000` | `instanceSyncDestroy` |
| `0x0A` | **Chat message** | `i32 color, str message, str tag` | `FUN_1003ece0` |
| `0x0B` | Chat mode | `u8 mode`, passed straight through from the `setChatMode` export (GML `gms_chat_team_only_*`, so most likely the team-only flag). Never sent in the capture. | `FUN_1003edb0` |
| `0x0C` | PlayerINI write | `NVar` | `playerINISet*` |
| `0x0E` | GameINI write | `NVar` | `gameINISet*` |
| `0x11` | PlayerINI delete | `str key` | `playerINIDelete` |
| `0x12` | GameINI delete | `str key` | `gameINIDelete` |
| `0x15` | **Resource manifest** (zlib-compressed asset-name table, one `u8 len + name` per entry; `snd_*`/`mus_*`/`spr_*`…). Uploaded once at login, after the server's five `0x14` enumeration requests (§5.5), so the server can reference resources by index. ✔ capture (38 KB → 103 KB inflated) | — |
| `0x16` | **P2P message** | `u8 targetIdx, u8 messageID, u8 argc, argc × TValue` ✔ | `FUN_1003d450` |
| `0x17` | "Player has account?" | `str name` | `playerHasAccount` |
| `0x20` | Admin kick | `u8 playerIdx, str reason` | `kickPlayer` |
| `0x21` | Admin ban | `u8 playerIdx, str reason, u32 duration` | `banPlayer` |
| `0x22` | Admin unban | `str name` | `gms_admin_unban` |
| `0x29` | Achievement reached | `u32 id` | `achievementReach` |
| `0x2B` | Highscore add/replace | `u32 listID, f64 score, u8 replace` | `addScoreNormal` |
| `0x2D` | Guest highscore | `str name, f64 score, u8 0` | `setHighcoreGuest` |
| `0x34` | Register account | `4 × str` | `registerUser` |
| `0x37` | Statistic set | `u32 id, f64 value` | `statisticSet` |
| `0x3A` | Friend request | `str name` | `friendRequest` |
| `0x3D` | Synced-instance variable | `u16 syncID−1000000, NVar` | `FUN_1003f4f0` (called from `FUN_10025300`) |
| `0x3E` | Synced-instance position | `u16 syncID−1000000, i32 x, i32 y, 3-byte packed direction/speed` | `FUN_1003f5c0` |
| `0x3F` | Synced-instance handover | `u16 syncID` | `instanceSyncTakeover` |
| `0x41` | Game version | `f64 version` | `FUN_1003f3a0` |
| `0x4B` / `0x4C` | BDB (binary DB) open (`0x4C` = with lock) | `u32 id`. The game's per-player profile DB is **`id = −playerID`** (as a 32-bit two's complement). ✔ both captures: after login the client opens its own (`4293732729` = 2³² − 1234567, your ID from `0x18`), and opening another user's profile opened theirs (`4292621618` = 2³² − 2345678, player `user_d`). The server answers with S→C `0x4B` for the same `id` (512 bytes each in game2). | `xGms_bdb_open` |
| `0x4D` | BDB close/commit | blob | `gms_bdb_close` |
| `0x5B` | VS mode end | — | `vsEnd` |
| `0x5C` | Session create | `u8 type, str tag` | `sessionCreateExt` |
| `0x5D` | Session join | `u16 sessionID` | `sessionJoin` |
| `0x64` | Ack to server `0x64` ping (bare, no payload) ✔ | — | `FUN_1003ec60` |
| `0x85`–`0x8A` | Name-cache slot definition | `u8 slot, str name, u8 type` ✔ | `FUN_1003fe90` |
| `0x8C` | Player-cache slot definition | `u8 slot, u64 playerID` ✔ | `FUN_10040290` |
| `0x8F` | **Set sending policy** (network tuning) | `u32 index, u8 policy` ✔ (capture: `1,1`) | `gms_optimize_set_sending_policy` → `FUN_1003c420` |
| `0x90` | Request data update | `u32, u32, u32, str` (the export returns a `rand()` request handle; the result comes back as S→C `0x3C`) | `gms_optimize_request_data_update` → `FUN_1003c310` |
| `0x96` | Environment report (at connect, then every 60 s) | `u32 envFlags`; **if non-zero**, followed by the module-scan list `u32 n, n × (str fileName, str sha1hex)` holding only entries **new since the last report** (§13.1) | `FUN_1003c0d0` → `FUN_1003bed0(buf, all=0)` |
| `0x97` | Keep-alive (every 10 frames, bare) ✔ | — | `Step` |
| `0x98` | **Module-scan query reply**. Sent only in answer to S→C `0x98 str query` | `u8 found` (any scan entry matched `query`); if found: `u32 n, n × (str fileName, str sha1hex)` with the **full** list (§13.1) | `FUN_1003c1a0` → `FUN_1003bed0(buf, all=1)` |
| `0x99` | Trusted transaction | `u8 transactionID, u8 argc (≤14), argc × TValue` (args set with `XGms_trusted_transaction_set_real/string`) | `XGms_trusted_transaction_send` → `FUN_1003d5e0` |
| `0x9B` | Auth-token challenge response (`str`, 128 hex) ✔ §5.4 | `str` | `FUN_1003d6e0` (from dispatcher) |
| `0xBE`–`0xFD` | **Own position / movement** | §7 | `FUN_1003d8f0` |
| `0xFF` | Logout / disconnect | — | `logout` |

---

## 7. Movement (walking around)

### 7.1 What the game syncs

Every frame, `gms_step` reports the local player's built-ins as player variables:
`x, y, direction, speed, room, sprite_index, image_index, image_speed, image_xscale, image_yscale, image_alpha, image_angle, image_blend`.

The DLL intercepts **`x`, `y`, `speed`, `direction`** (`setPlayerVarReal`) into a dirty bitmask
(bit0 = x, bit1 = y, bit2 = speed, bit3 = direction) and sends them with the compact message below. Every other
variable (`room`, sprite fields, …) goes out as a generic `0x03` player variable.

Other players are drawn by `obj_other_player`, which reads them back with `gms_other_get(id, "x"|"y"|"room"|…)`.

### 7.2 Send policy (dead reckoning)

- Rate-limited by `gms_optimize_set_sendspeed` (latency ms; no limit if < 50 ms).
- If only x/y changed and the position extrapolated from the last sent speed/direction is within **0.5 px**, the
  update is skipped (up to `gms_optimize_set_max_skip` times in a row).
- **Every 50 frames** all four fields are force-resent. ✔ game2: while standing, a full update every ~1.7 s
  (50 frames at 30 fps).

**What walking actually looks like (✔ game2).** The game moves the player by setting `x`/`y` directly, so
`speed` and `direction` stay `0` and are only sent in the periodic full resends (as mode 2, `00 → dir 0, speed 0`).
While walking, every frame carries only the axes that changed: `0xCE` (x as u16, no dir/speed byte) for horizontal
steps of 3 px, `0xC2`/`0xCA` for y-only steps, and `0xEE` (12+12 packed x/y, no dir/speed byte) when both change.
Sprite changes go out alongside as `0x03` vars (`sprite_index`, `image_index`, `image_speed`). Every remote position
seen in both captures also had dir/speed `0`.

### 7.3 Wire format

C→S: `u8 (0xBE + flags)`, then the fields. S→C: same ID range with **`u8 player`** inserted after the ID.

`flags` is a 6-bit value (`id − 0xBE`, 0–63):

```
bits 5-4 : X mode     bits 3-2 : Y mode     bits 1-0 : speed/direction mode
```

**Position** (X mode / Y mode):

| X | Y | Bytes | Meaning |
|---|---|---|---|
| 0 | – | – | x unchanged |
| 1 | – | u16 | x |
| 2 | – | i32 | x |
| – | 0 | – | y unchanged |
| – | 1 | u16 | y |
| – | 2 | i32 | y |
| – | 3 | u8 | y = byte × 2 |
| 3 | 0 | 3 bytes | packed 12+12 bits: `x = ((b1 & 0xF) << 8) \| b2`, `y = (b0 << 4) \| (b1 >> 4)` (0–4095) |
| 3 | 1 | u8, u8 | x, y (0–255) |
| 3 | 2 | u8, u8 | x = b×2, y = b×2 (even values ≤ 510) |
| 3 | 3 | – | x = y = 0 |

Encoder choice (client): both 0 → `3/3`; both in 0–255 → `3/1`; both even and ≤ 510 → `3/2`; ≤ 4095 → `3/0`;
≤ 65535 → `1/1`; otherwise `2/2`. With only one axis dirty: x → u16 or i32; y → u8×2 (even, < 510), u16 or i32.

**Speed / direction** (only present if bytes remain in the frame):

| Mode | Bytes | Decode |
|---|---|---|
| 0 | u8 | `direction = b / 240 · 360` (speed unchanged) |
| 1 | u8 | `speed = b / 8 − 16` (direction unchanged) |
| 2 | u8 | `direction = (b >> 4) · 22.5`, `speed = (b & 0xF) − 8` |
| 3 | 3 bytes | 12+12 packed into a **big-endian** 24-bit value `v = b0<<16 \| b1<<8 \| b2` (same bit order as the 12+12 position): `direction = (v & 0xFFF) / 11`, `speed = (v >> 12) / 80 − 25.6` |

Byte order of mode 3 (and of every other 3-byte dir/speed field: S→C `0x04`, `0x3E`, instance create): every
sample in both captures (129 S→C `0xE9` snapshots, all of them standing players) is `80 00 00`. Read big-endian,
that is speed 0 / direction 0; read little-endian it would be speed −25.6 / direction 11.6°. No moving sample has
been captured yet, so the reading is strongly supported rather than proven.

Mode 2 is used when the direction is a multiple of 22.5° and speed is in [−8, 7], which covers normal 8-way walking.

---

## 8. Player variables (the "interact with the world" state)

Generic `0x03` (C→S `NVar`; S→C `u8 player` + `NVar`). Set with `gms_self_set(name, value)`, read with
`gms_other_get(playerID, name)`. Variable names recovered from the game's call sites:

| Area | Variables |
|---|---|
| Presence / status | `afk`, `chatting`, `localchat`, `admin_invisible`, `directmsg` (DMs enabled), `area` (current map — values `hub`, `ruins`, `snowdin`, `waterfall`, `hotland`, `core`, `newhome`, `lost`, `void`, `fohad`, `deltatown`, `darkworld3`, `darkworld4`, `cyber`, `blank`) |
| Identity / profile | `myname`, `gname`, `mylv`, `myrank`, `mykills`, `myspares`, `mybadge`, `myskin`, `skin`, `skinlock`, `myfile`, `myfriends`, `partner`, `partyname`, `pf_aboutme`, `pf_avatar`, `pf_background`, `pf_likes`, `pf_love`, `pf_mobile`, `pf_partner`, `pf_partnerid`, `pf_partnerflv`, `pf_partnerfxp`, `pf_power`, `pf_rank`, `pf_skinindex`, `pf_team` |
| Local-chat bubbles | `pf_message1`, `pf_message2`, `pf_message3` |
| PvP / battle | `myhp`, `mymax`, `myEN`, `myAction`, `opponent`, `pvpready`, `turn`, `requestspare`, `pvp_dmg`, `pvp_msg_line1`, `pvp_msg_line2`, `pvp_soulx`, `pvp_souly`, `pvp_soulhit`, `pvp_soulimage`, `pvp_soulsprite`, `mypvpwins`, `mypvpstreak` |
| FFA mode | `ffa_hp`, `ffa_run` |

During PvP the heart (soul) position is streamed through `pvp_soulx`/`pvp_souly` player variables, not a dedicated message.

Persistent account data (save files) uses **PlayerINI** (`0x0C`/`0x11`, written by `scr_savemulti`,
`scr_autosave*` etc.); world counters use **GameINI** (`0x0E`/`0x12`).

---

## 9. Chat

### 9.1 Global / local chat (server-relayed)

- **Send:** `gms_chat(text, color)` → `XServer_chat_send_message(text, color, tag)` → **`0x0A`**
  `i32 color, str message, str tag`. ✔ capture: typing **"hi"** sent `0a ffffff00 0200 "hi" 0000` — color
  `0x00FFFFFF` (white), message "hi", **empty tag**. The colour is **not fixed**: it is the sender's chat colour
  (BGR). ✔ game2: `user_b` sent both its global and its local line with `0x007B7B7B`, and received lines carried
  `0x0000FF`, `0xFFFFFF` and `0x22BBD1` (BGR) depending on the sender.
- **Global vs. local (✔ game2).** Global chat is a bare `0x0A` with an empty tag, bracketed by the player var
  `chatting = 1` (input box opened) and `chatting = 0`. Local chat is `0x0A` with tag `"localchat"`, bracketed by
  `localchat = 1` / `localchat = 0`, followed by `pf_message1 = <text>` (the speech bubble), and preceded by a
  **one-time synced instance** `0x1A` (object 1571) carrying the chat-history record: vars
  `name, pid, msg, fnt, color, icon, icnum` (§10; `pid` is your player ID as a string, `color` the same chat colour).
- The server does **not** echo your own `0x0A` back (neither capture contains a relay of the client's own line).
- **Receive:** S→C **`0x0A`** `u8 player, i32 color, str message, str tag` → GMS action with fields
  `color, message, strlen, tag`, delivered to the game's `scr_receivechat` (set via `gms_script_set_chat_receive`).
  ✔ capture: a received local line arrived as `0a 0d <color> <29-char message> "localchat"`. The **channel is carried
  in the `tag` string** (`"localchat"` for local chat; empty/other for global), so no separate `0x0B` was needed in
  the capture — `0x0B` (chat mode) was never sent.
- Client-side handling in `scr_receivechat`: banned-word censoring (`$%@&`), `chat received` / `local received`
  routing. `obj_globalchat_mobile` and `obj_rp_localchat` / `obj_localchat_mobile` are the UIs.
- Local speech bubbles are also mirrored into the `localchat` and `pf_message1..3` player variables, and
  `GMS_Alarm_5` syncs chat-history instances with variables `name, pid, msg, fnt, color, icon, icnum` (✔ game2,
  see above).

### 9.2 Direct messages and guild chat (P2P)

DMs and guild chat do **not** use `0x0A`. They are P2P messages `4` and `24` (§11).

### 9.3 Slash commands (client-side, `scr_commands`)

These are parsed locally and translated into player-var changes, P2P messages or local actions:
`/afk /brb /invis /speed /ffa /br /pvp [on|off|list] /players /friends /dm on|off /bubble /warp /respawn /arcade /skins /chatstyle /localstyle /namecolor <color> /dailygift /encounters on|off /autorun /autosave /localfreeze /localopacity /msglimit /session 1-4 /undernet /help`,
plus admin-only `/tp /fun /mute /ban /gms-kick /unban /adminenable /adminname /admintoggle /clearart /event <name> /freegold`.
Messages starting with `@guild` become guild chat (P2P 24).

---

## 10. Synced instances (projectiles, chat-history objects)

Used for PvP attack spawners (`obj_bombspawner`, `obj_firespawner`, `obj_knifer_spawner`, … each syncs a
`master` variable), the player's `creator` link, and chat-history objects. ✔ game2: sending a local chat line
created a one-time instance `1a 0b 23060000 00 14 08 07 <7 × NVar>` (flags `0x0B`: u32 object 1571, X/Y mode 0 →
u8 x = 0, u8 y = 20, 1-byte dir/speed `08` = direction 0 / speed 0, var count 7 in an extra u8), which parses exactly under the layout below. API: `gms_instance_sync(inst, kind)`
plus `gms_instance_sync_var_add(name, …)`.

C→S create (`FUN_1003e200`); S→C is identical but with **`u8 ownerPlayer`** right after the ID (`FUN_10027af0`):

| ID | Kind |
|---|---|
| `0x1A` / `0x1B` | one-time (`is_onetime`: fire-and-forget; no sync ID) |
| `0x08` / `0x1C` | extended (`is_extended`: has sync ID) |
| `0x1D` / `0x1E` | full (`is_full`: has sync ID; owner keeps updating) |

**Paired IDs.** `instanceSyncOnce/Ext/Full` each take a leading numeric argument that is forwarded to the
encoder as a `double`. The encoder sends the first ID of the pair when it is `0.0` and the second when it is non-zero.
On the **receiving** side (`FUN_10027af0`) the DLL treats both IDs of a pair identically: it only branches on the kind
(`26/27`, `8/28`, `29/30`), and both IDs of a pair produce the same GML action (4, 13 or 14). So the flag only matters
to the **server** (presumably a relay or scope option), and the client never sees what it means. The GML caller
(`gml_Script_gms_instance_sync`) only accepts `is_onetime`, `is_extended` and `is_full` as kinds.

Other encoder facts:
- Before an extended or full create, the client makes sure its own `room` player variable is up to date and sends
  it as `0x03` if not ("Note: Extra room variable created"). The created instance also stores the owner's `room`.
- Sync IDs come from the client's own range: `syncID = 1000000 + base + (counter mod 1000)`, where `base` is assigned
  by S→C `0x19`. That gives at most 1000 concurrent synced instances per client, enforced with an error message.

```
[u16 syncID − 1000000]            (not for one-time)
u8  flags
object_index : u8, or u32 if flags & 0x08
x/y          : per flags bits 7-6 (X) and 5-4 (Y):
                X: 0=u8 1=u8·2 2=u16 ; Y: 0=u8 1=u8·2 2=u16 3=i32
                X=3 → Y=0: x=y=0 | Y=1: one u16 for both | Y=2: 12+12 packed | Y=3: i32 x, i32 y
dir/speed    : 1 byte (dir = hi4·22.5, speed = lo4−8) if !(flags & 0x04), else 3-byte 12+12 packed (§7.3 mode 3)
varCount     : flags & 3, or an extra u8 if (flags & 3) == 3 (max 16)
varCount × NVar
```

Encoder choice for x/y (`FUN_1003e200`): both 0 → `X3/Y0`; `x == y` and ≤ 0xFFFF → `X3/Y1`; both in 255…4096
and each odd or > 510 → `X3/Y2` (12+12); otherwise per axis: ≤ 255 → `u8`, even and ≤ 510 → `u8·2`, ≤ 0xFFFF →
`u16`, else `X3/Y3` (two `i32`). `object_index` > 255 sets flag `0x08`. Flag `0x04` is set when the direction is not
a multiple of 22.5° or the speed is outside [−8, 7].

Updates: `0x3D` (variable: `u16 id, NVar`), `0x3E` (position: `u16 id, i32 x, i32 y, 3-byte 12+12 dir/speed`),
`0x3F` (owner/handover), `0x09` (destroy). Sync IDs are carried as `id − 1000000` in a u16.

---

## 11. P2P messages (game-level protocol)

### 11.1 Wire

`gms_p2p_send(message_id, target, arg0, arg1, …)`. The GML wrapper calls `XServer_p2p_set_real/string(i, argᵢ)`
for each extra argument (max 14), then `XServer_p2p_send(target, message_id)`:

```
C→S 0x16 : u8 targetIdx (player cache, see 0x8C), u8 messageID, u8 argc, argc × TValue
S→C 0x16 : u8 senderIdx,                          u8 messageID, u8 argc, argc × TValue
```

`target = 0` in GML means **broadcast**: on the wire it becomes client cache index `0xFF`, which the client first
defines as player ID `0` (`8c ff 00…00`). ✔ both captures (game2 bytes): `16 ff 16 01 7c 06 "user_b"` (P2P 22 to all, one `str8` argument). The server
relays a broadcast **to the sender too**, so you receive your own P2P 22 back (in game2 the server first defined a
new S→C player-cache index for your own ID just for this).

Incoming P2P messages go to `scr_receivep2p(message_id, sender, argsList)`. It first checks the sender is valid
(`gms_other_find_by_name(gms_other_get_string(sender, "name")) ≠ -1`), then `switch (message_id)`.

### 11.2 Message catalogue

`name20` = `string_copy(gms_self_name(), 1, 20)`.

| ID | Purpose | Sent by | Target | Args | Receiver behaviour |
|---|---|---|---|---|---|
| 0 | PvP damage hit | `obj_hit` Alarm 0 | `obj_game.opponentid` | — | reads sender's `pvp_dmg` (capped at 9), subtracts it from HP, `gms_self_set("myhp", …)` |
| 1 | PvP spare request | `obj_selector` | opponent | — | spawns `obj_requestspare` if in battle with sender |
| 2 | PvP spare accepted / flee / end | `obj_selector` | opponent | — | `obj_spare` / `obj_flee` / `obj_youwon` |
| 3 | PvP / co-op heart action | `scr_bullethandler`, `obj_heartmove_coop` | opponent | list values | updates `myhead` / HP for the battle |
| 4 | **Direct message** | `obj_senddm`, `obj_un_otherprofile` | `gms_other_find_by_name(name)` | `string(senderName)`, `text` (profile variant has 5 args) | honours `directmsg` and `safetymode`; checks friend status (`gms_friend_name`); shows `scr_notification` |
| 5 | (empty case) | — | — | — | no-op |
| 6 | Feed: "<name> GAINED LOVE!" | `obj_youwon` | 0 (all) | `name20` | pushes into the activity feed `obj_game.fname1..5 / feed1..5 / fcon1..5` |
| 7 | Feed: "WON A PVP MATCH!" | `obj_youwon` | 0 | `name20` | feed |
| 8 | Feed: "UPDATED THEIR STATUS!" | `obj_un_upd_aboutme`, `obj_lateststatus_mobile` | 0 | `name20` | feed |
| 9 | Feed: "POWERED UP IN FFA!" | `obj_player` collision | 0 | `name20` | feed |
| 10 | Feed: "EDITED THEIR PROFILE!" | `obj_un_chg_back` | 0 | `name20` | feed |
| 11 | **Admin summon/kick to Ruins** | `obj_other_player` right-click | clicked `player_id` | — | only if sender's `gms_other_admin_rights` > own: `gms_self_set("area","ruins")`, stops audio, fades to Ruins |
| 12 | PvP effect "SLOWDOWN" | `obj_pvpfight` | opponent | — | applies slowdown if in battle with sender |
| 13 | PvP effect "CONFUSION" | `obj_pvpfight` | opponent | — | applies confusion |
| 14 | **Gold transfer** | `obj_banktransfer`, `obj_un_bank` | `otherid` | `amount` (`withdraw`) | adds to `g`, sets `lasttransfer`, notifies "<name> (<friend>) sent <n>G!" |
| 15 | Feed: "GOT A NEW PARTNER!" | `obj_youwon` | 0 | `name20` | feed |
| 16 | Feed: "POSTED NEW ART!" | `obj_un_upd_draw` | 0 | `name20` | feed |
| 17 | PvP ready / battle handshake | `obj_setbattle` Create | `opponentid` | `room` | sets `obj_game.ready` |
| 18 | Admin/server command | `scr_commands` | 0 | `name20` | checks admin rights, reloads art DB (`gms_bdb_open`), timed alarm |
| 19 | Guild reward share | `obj_youwon` | each guild member | values | adds guild members' EXP/gold/spares/kills (`partytotal_*`), notification "+EXP / GOLD / SPARE / KILL" |
| 20 | Guild: member joined | `obj_un_partysetup` | `member1_id..member3_id` | — | reads sender `partyname`, updates `member1..3_name`, notification "… joined the guild!". ✔ game2: joining a guild whose members were offline sent **only** the player var `partyname = <guild name>`, no P2P. |
| 21 | Guild: member left | `obj_un_partysetup` | members | — | "… left the guild." |
| 22 | Friend came online | `obj_multimenu` (on connect) | 0 | `gms_self_name()` | if sender is a friend: "<name> has connected!" |
| 23 | (empty case) | — | — | — | no-op |
| 24 | **Guild chat** | `scr_commands` (`@guild …`) | guild members | text | profanity filter (`bannedwords`, `safetymode`), timestamps, prints `[GUILD] name: text` via `scr_receivelocal` |

---

## 12. Server → Client message catalogue

`u8 player` = player-cache index (§4.2). "Action N" means the DLL queues GML action N for `gms_step` (§12.1).
All entries come from the dispatcher `FUN_1002c100`.

| ID | Meaning | Payload |
|---|---|---|
| `0x01` | Connection confirmed | `u32 identifier` (logged as "Received identifier"; sets the *connected* flag) |
| `0x02` | Login result | §5.3 |
| `0x03` | Other player's variable | `u8 player, NVar` |
| `0x04` | **Legacy absolute position** | `u8 player, i32 x, i32 y, 3-byte 12+12 dir/speed` (`direction = low12/11`, `speed = high12/80 − 25.6`, same as §7.3 mode 3). Applied straight to the player's position setter. Superseded by `0xBE`–`0xFD`; not seen in capture. |
| `0x05` | Player presence | `u8 status, u8 player` [+ `str name` when status 0/2]. 0 = logged in (action 1, "… logged in"), 1 = logged out (action 2), 2 = joined your session (action 31), 3 = left your session (action 32). ✔ capture: the initial roster arrived as 37 × `05 00 <player> <name>`. ✔ game2: switching sessions (`0x5D`) produced status **1** for the players of the old session and status **0** for the 40 players of the new one, not 2/3; statuses 2/3 were not seen in either capture |
| `0x06` | Global variable | `NVar` |
| `0x07` | **Team score** | `u8 team, u32 bits` stored as an **f32** into the 11-slot team-score table read by `teamGetScore`. Same layout as C→S `0x07`. (`gms_protect_*` is local memory obfuscation and never goes on the wire.) |
| `0x08`, `0x1A`–`0x1E` | Synced instance created | §10 (actions 4 / 13 / 14 by kind) |
| `0x09` | Synced instance destroyed | `u16 syncID−1000000` (action 11) |
| `0x0A` | **Chat** | `u8 player, u32 color, str message, str tag` (action 3: `color, message, strlen, tag`) |
| `0x0C` / `0x0D` | PlayerINI value / error | `NVar` / no payload. `0x0D` only raises the error "The server is sending corrupt PlayerINI data". |
| `0x0E` / `0x0F` | GameINI value / error | `NVar` / no payload ("… corrupt GameINI data") |
| `0x10` | Server error | `str` → passed to the GMS error reporter |
| `0x13` | VS mode ready | — (sets *vsIsReady*; action 30 → `gms_script_set_vs_begin`) |
| `0x14` | **Resource-enumeration request** | `u8 kind` (0 sounds, 1 objects, 2 rooms, 3 scripts, 4 sprites) → action 6, which makes the game upload the C→S `0x15` manifest (§5.5). ✔ capture: five in a row, kinds 0–4 |
| `0x15` | **Server sound command** | `u32 soundIndex, u8 op` → action `7 + op`: 0 = play, 1 = `sound_loop`, 2 = stop (the game checks `sound_exists` first). `soundIndex` refers to the `0x15` manifest. |
| `0x16` | **P2P** | `u8 sender, u8 msgID, u8 argc (≤15), argc × TValue` (action 10) ✔ (capture: sender relays msg 22 "user_e"→15) |
| `0x17` | **"Player has account?" reply** | `str name, u32 result`: answers C→S `0x17` and is stored in the map read by `playerHasAccount(name)` |
| `0x18` | **Own player ID** | `u64 playerID`: the value returned by `playerID()` and used by `isMaster`, `instanceIsOwner`, etc. |
| `0x19` | **Instance sync-ID base** | `u16 base, u16 (read and ignored)`. Seeds both the base and the counter used for this client's synced-instance IDs (§10) |
| `0x23` | **Limits** | `u32 maxGameINI, u32 maxPlayerINI, u32 numGameLogins`: the values behind the exports of the same names |
| `0x28` | Achievement definition | `u32 id, str name, str description` |
| `0x29` | Achievement reached | `u32 id` (marks it reached locally; error if the id is unknown) |
| `0x2A` / `0x2B` / `0x2C` | Highscore list / entry / clear | `u32 id, str title` / `u32 list, str name, f64 score` / `u32 listID`. ✔ both captures: all ten `0x2A` titles come first, then each list is sent as one `0x2C <listID>` immediately followed by that list's 500 `0x2B` entries, so `0x2C` empties a list before it is refilled **(inferred from the order)** rather than deleting it |
| `0x2D` | **Guest-highscore result** | `u8` (read by `setHighcoreGuest`; action 41) |
| `0x2E` | Friend entry | `u64 playerID, str name` (raw 8-byte ID, not an f64) |
| `0x2F` / `0x30` | Friend online / offline | `u64 playerID` (actions 15 / 16, "… is online/offline") |
| `0x31` | Own admin rights | `u8` |
| `0x32` | Logged in as guest (name gets `Guest_` prefix) | — |
| `0x33` | Other player's admin rights | `u8 player, u8 rights` |
| `0x34` | Registration status | `u8` (`registerGetStatus`; action 35) |
| `0x35` | Master (host) player | `u8 player` |
| `0x36` / `0x37` | Statistic definition / value | `u32 id, str name, str description` / `u32 id, f64 value` |
| `0x38` | **Server clock** | `u32 seconds`, timestamped with `GetTickCount()`; `serverTime() = seconds + elapsed_ms/1000` |
| `0x3A` | **Friend-request result** | `u8` (answers C→S `0x3A`; action 36) |
| `0x3C` | Data-update result | `NVar` (action 18; answers C→S `0x90`) |
| `0x3D` / `0x3E` / `0x3F` | Instance var / position / owner | `u16 id, NVar` / `u16 id, i32 x, i32 y, 3-byte 12+12 dir/speed` / `u16 id, u8 player` |
| `0x41` / `0x42` | Update available / none | `str url` (enables `startUpdate`) / — |
| `0x4B` / `0x4C` | BDB blob data / lock | `u32 req, u32 len, bytes` (action 40) / `u32 req, u8 locked`. ✔ both captures: `req` echoes the `id` of the C→S `0x4B` open (§6), e.g. `−playerID` for a profile |
| `0x50` | **Server command `room_goto`** | `u32 room` → action 21: `room_goto(room)` if `room_exists` ("Server command: …") |
| `0x51` / `0x52` / `0x53` | **Server commands** | — → actions 22/23/24: `room_goto_next()`, `room_goto_previous()`, `room_restart()` |
| `0x54` | **Server command: sound** | `u32 soundIndex` → action 25 (same native call as `0x15` op 2: stop the sound) |
| `0x55` | **Server command `sound_stop_all`** | — → action 26 |
| `0x5A` | VS time left | `u32` (`vsTimeLeft`) |
| `0x5B` | VS ended (clears players and instances) | — (action 29) |
| `0x5C` | Current session ID | `u16` (action 28 → `gms_script_set_session_change`) ✔ (capture: 803, later 3) |
| `0x5E` | Session list | `u8 n, n × (u32 id, u8 type, u8 players, str tag)` ✔ (capture: session 3 = 37 players) |
| `0x61` | (ignored) | `u32, u32`, read and discarded |
| `0x62` | **Dead feature** | `u32 id, str ip`: appended as `(sockaddr ip:25512, id)` to an internal vector that **nothing ever reads** (only its destructor touches it). No connection is made. Not seen in capture. |
| `0x64` | **Ping** — client replies with a bare `0x64` | `u8 b` ✔. `pingTime() = 3·b` ms, so `b` is the server-measured RTT / 3 (range 0–765 ms). Sent about once per second ✔ |
| `0x65` | **Ping, high range** | `u8 b`, same handler and ack, but `pingTime() = 765 + 3·b` ms (765–1530 ms). Not seen in capture. |
| `0x83` | Own username changed | `str` ✔ (capture: "user_a") |
| `0x84` | Geo-location | `u32 iso, str countryName, str countryCode, str languages` ✔ (capture: `<iso>, "<country>", "<CC>", "<lang>"`, values redacted) |
| `0x85`–`0x8A` | Name-cache definition (per table: 0x85 player vars, 0x87 PlayerINI, 0x88 GameINI, …) | `u8 slot, str name, u8 type` ✔ |
| `0x8C` | Player-cache definition | `u8 slot, u64 playerID` ✔ |
| `0x90` | Callback | `u32` → action 50 (the game runs a registered script if it exists) |
| `0x91` | Auth token | `str authToken` (base64, 128 chars) → action 51 / `gms_script_set_authentication_token_received` ✔ |
| `0x98` | **Module-scan query** | `str query` → client answers C→S `0x98` (§13.1). Not seen in capture. |
| `0x99` | Trusted-transaction result | `u8 transactionID (ignored), u8 ok` [+ `TValue result` if `ok == 1`] → action 52 / `gms_script_set_trusted_transaction_result` |
| `0x9A` | **Trusted-transaction log** | `str` → stored and returned by the export `gms_trusted_transaction_log()`. Not seen in capture. |
| `0x9B` | Auth-token challenge (`str`, base64 128 chars); client replies `0x9B` (§5.4) ✔ | `str` |
| `0xBE`–`0xFD` | **Other player's movement** | `u8 player` + §7.3 |
| `0xFE` | Fatal error | `str` → message box, process exits |
| `0xFF` | **Kicked** | `u8 status, str message` → socket closed; `status` goes to the connection-status setter (0 = connected, 1 = disconnected, other = unknown); logout; action 20 → `gms_script_set_kick` |

Any other ID raises "`<id>` is not a valid messageID".

### 12.1 GML action IDs (what the game does with each S→C message)

The DLL never calls game code directly. It queues *actions* that `gml_Script_gms_step` drains through a 53-way
switch (`DONTFORGET.exe` `0x21091AD`; IDs 12, 33, 37–39 and 42–49 fall through to "Unknown action ID"). Where a
case calls GML builtins or uses strings, the behaviour below was read from them; YYC resolves builtins through a
`{name, index}` table, so they appear by name. Entries marked † have no telling builtin in the case body, so they are
named from the DLL side and the matching `gms_script_set_*` setter.

| Action | Source | Game-side behaviour |
|---|---|---|
| 1 / 2 | `0x05` status 0 / 1 | player logged in / logged out ("… logged in" / "… logged out") |
| 3 | `0x0A` | chat: `ds_list_add` with sender and `current_time` into the chat history |
| 4 / 13 / 14 | `0x1A`/`0x1B`, `0x08`/`0x1C`, `0x1D`/`0x1E` | "Received instance to sync: is_onetime / is_extended / is_full" → creates the object |
| 6 | `0x14` | resource enumeration (§5.5) |
| 7 / 8 / 9 | `0x15` op 0 / 1 / 2 | sound play / `sound_loop` / stop |
| 10 | `0x16` | P2P → `gms_script_set_p2p` script ("…no script is set to handle P2P messages" otherwise) |
| 11 | `0x09` | destroy synced instance |
| 15 / 16 | `0x2F` / `0x30` | friend online / offline ("… is online" / "… is offline") |
| 17 | (achievement) | "Achievement unlocked: …" notification |
| 18 † | `0x3C` | data-update result script |
| 19 | (connection loss) | "Disconnect" → connection-lost handling |
| 20 † | `0xFF` | kick script |
| 21–24 | `0x50`–`0x53` | `room_goto(arg)`, `room_goto_next`, `room_goto_previous`, `room_restart` |
| 25 / 26 | `0x54` / `0x55` | sound stop / `sound_stop_all` |
| 27 | resource download | "Resource locked & loaded" |
| 28 † | `0x5C` | session-change script |
| 29 / 30 † | `0x5B` / `0x13` | VS end / VS begin scripts |
| 31 / 32 † | `0x05` status 2 / 3 | player joined / left session |
| 35 / 36 | `0x34` / `0x3A` | registration / friend-request callbacks (run a script if `script_exists`) |
| 40 | `0x4B` | BDB blob loaded (runs the request's script if `script_exists`) |
| 41 | `0x2D` | guest-highscore callback (`script_exists` → script) |
| 50 / 51 / 52 | `0x90` / `0x91` / `0x99` | callback / auth-token-received / trusted-transaction-result scripts (each gated by `script_exists`) |

---

## 13. Anti-cheat / telemetry notes

- The handshake and the 60-second `0x96` report carry an **environment flag word** (debugger, VM and sandbox checks)
  and **hardware fingerprints** built from WMI motherboard/BIOS serials.
- The server runs a `0x9B` challenge–response using a per-game client secret, plus a `0x91` auth token. **This gates
  login**: an unanswered or wrong `0x9B` yields login error 15 ("client unauthenticated"). Details in §5.4.
- `0x64` is an ordinary keep-alive ping (its byte is the server-measured RTT / 3, with a bare ack), **not** an
  integrity check.
- The game itself broadcasts `"I CHEATED! ID: …"` / `"I CHEATED! REPORT ME! ID: …"` through `gms_chat` (`GMS_Alarm_5`)
  when its own integrity checks fail.

### 13.1 Module scan and the `0x98` query

`Dll.dll` runs a background thread (`FUN_10011300`) that wakes **every 5 s**, but only does work while the
environment check `FUN_1000ee20` returns non-zero. Each pass:

1. lists every module loaded in the game process (`EnumProcessModules` + `GetModuleFileNameExA`);
2. also takes the executable of the current **foreground window's** process, if it belongs to another program;
3. passes each path not seen before to `FUN_10010040`. It skips paths that start with `C:\Windows\` or
   `C:\ProgramData\Microsoft\Windows Defender` and checks the rest for any of the substrings `cheat`, `click`,
   `debug`, `artmoney`, `scanmem`, `gameconqueror`, `squalr`, `hack`, `pwn`, `cosmos`, `dbg`, `.dll`, `crysearch`,
   `tsearch`, `olly` (the complete list; the path is passed through a `std::locale`, presumably to lower-case it).
   Because `.dll` is on the list, **every DLL loaded from outside `C:\Windows\` gets recorded**, including the game's
   own extension DLLs and any injected module;
4. on a hit, records `(fileName, sha1hex)` in a mutex-guarded list. `fileName` is the path after the last separator.
   `sha1hex` is the CryptoPP **SHA-1** of the file's first 32 MiB, or `"-"` if the file cannot be opened.

That list goes to the server in two ways, both serialized by `FUN_1003bed0` as `u32 n, n × (str fileName, str sha1hex)`:

- **`0x96` environment report** (connect + every 60 s): appended when `envFlags ≠ 0`, holding only entries added
  since the previous report.
- **`0x98` query**: the server sends `0x98 str query`, and the client answers `0x98 u8 found` (whether any recorded
  entry matched `query`), plus the **entire** list when `found` is set.

---

## 14. Verification status and open questions

**Seen in the capture:** transport, framing, value encoding and caches; handshake and login (success ⟺ status `== 1`;
login fails with error 15 until `0x9B` is answered); the `0x9B` response; movement in both directions (own
`0xF2/0xF4/0xFC`, others' `0xE9`); chat in both directions; the P2P framework (P2P messages 15 and 22); INI,
highscore, session and BDB traffic; and the resource enumeration and manifest. `game2.pcapng` adds: walking
(x-only / y-only / both-axis movement IDs), warping (session re-join + `room`/`area` vars), local chat and its
one-time chat-history instance (`0x1A`), the per-player profile BDB (`id = −playerID`), friend entries (`0x2E`),
own player ID (`0x18`), and a guild join (player var only).

**Code only (not exercised in the capture):** admin commands, trusted transactions, VS/battle, guild, instance sync,
server commands `0x50`–`0x55`, and `0x04`, `0x62`, `0x65`, `0x98`, `0x9A`.

**Open questions:**
- Field meanings of C→S `0x34` (register, 4 strings) and `0x90` (data-update request, 3 × u32 + string).
- The server-side meaning of the instance-sync paired-ID flag (§10).
- Argument lists of P2P messages 3, 19 and 24 (§11.2).
- A few names in the player-variable table are actually values (the `area` names).
- The byte order of the 3-byte dir/speed field needs a sample from a player whose `speed`/`direction` is non-zero
  (§7.3). Normal walking never produces one.
- Whether `0x2C` clears a highscore list (as the capture order suggests) or deletes it.

### Key addresses (`Dll.dll`, image base `0x10000000`)

`FUN_1002c100` S→C dispatcher · `FUN_10030330` recv/deframe · `FUN_100385b0` frame writer · `FUN_100387a0` handshake frame ·
`FUN_10025d90`/`FUN_1003a990` TValue read/write · `FUN_10026060`/`FUN_1003af60` NVar read/write ·
`FUN_1002bcc0`/`FUN_1003d8f0` movement read/write · `FUN_10027af0`/`FUN_1003e200` instance sync read/write ·
`FUN_1003c500` login · `FUN_1003baf0` handshake · `Step` (`0x100308d0`) main loop ·
`FUN_1003d6e0` `0x9B` response writer · `FUN_1001e920` string concat (`challenge ∥ secret`) ·
`gms_settings_set_game_secret` (`FUN_10004710`, export #77) stores the secret into `DAT_101b2b38` (image offset `0x1b2b38`) ·
`FUN_1001b9d0` GML-action constructor · `FUN_10027650` sync-ID allocator · `FUN_1003f4f0` C→S `0x3D` writer ·
`FUN_1003fb70` C→S `0x07` writer · `FUN_1003c1a0` C→S `0x98` reply · `FUN_1003bed0` scan-list serializer ·
`FUN_10011300` module-scan thread · `FUN_10010040` keyword filter · `FUN_1000fcc0` SHA-1 of file.

### Key functions (`DONTFORGET.exe`, YYC)

`gml_Script_scr_receivep2p` (0xF51FE0) · `gml_Script_gms_p2p_send` (0x21CB850) · `gml_Script_scr_commands` ·
`gml_Script_scr_receivechat` · `gml_Object_GMS_Create_0` (init) · `gml_Object_GMS_Alarm_5` (chat/instance sync) ·
`gml_Script_gms_step` (`0x20F6EE0`; action switch at `0x21091AD`, resource-kind switch at `0x20FBB95`) ·
`gml_Script_gms_instance_sync` (`0x21C8770`).
