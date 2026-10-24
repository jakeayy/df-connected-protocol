# DF CONNECTED v2.7.15 — Text Formatting Reference

How text is coloured, styled and typed out in `DONTFORGET.exe` (YYC-compiled GML). Companion to `PROTOCOL.md`.

Everything here was read from the compiled code; nothing was confirmed by running the game. Statements are
**(observed)** unless marked **(inferred)**, meaning reasoned from surrounding code, or **(unresolved)**.

Colours are GameMaker **BGR** integers (`0xBBGGRR`); RGB hex is given alongside. Sound and object names come from
the game's embedded resource tables (`SOND`, `OBJT`).

## Table of contents

1. [Summary — what a player can actually type](#1-summary--what-a-player-can-actually-type)
2. [`/namecolor` presets and style settings](#2-namecolor-presets-and-style-settings)
3. [Global chat rendering (`scr_drawchat`)](#3-global-chat-rendering-scr_drawchat)
4. [Local chat history — backtick codes (`scr_veil_drawchat`)](#4-local-chat-history--backtick-codes-scr_veil_drawchat)
   - [4.1 How history entries are stored (`scr_receivelocal`)](#41-how-history-entries-are-stored-scr_receivelocal)
5. [Typewriter `\` escapes (speech bubbles, dialogue box, act/battle text)](#5-typewriter--escapes-speech-bubbles-dialogue-box-actbattle-text)
   - [5.1 Shared escapes](#51-shared-escapes) · [5.2 Dialogue-box-only escapes](#52-dialogue-box-only-escapes) · [5.3 Typing speed, glyph spacing and newlines](#53-typing-speed-glyph-spacing-and-newlines) · [5.4 Choice prompts (`^` pauses)](#54-choice-prompts--pauses)
6. [Chat-related synced data](#6-chat-related-synced-data-cross-ref-protocolmd)
7. [Open questions](#7-open-questions)

---

## 1. Summary — what a player can actually type

| Where | Inline markup a user can type? | How colour gets there |
|---|---|---|
| **Global chat** (`scr_drawchat`) | **No.** The message text is drawn as plain text. | The colour integer in the chat packet (`gms_chat(text, color)`), plus fixed colours for special cases (§3). |
| **Local chat history** (`scr_veil_drawchat`) | **Yes (inferred):** `` ` `` + one character switches colour (§4). | The game itself writes `` `c … `w `` around names. |
| **Speech bubbles / dialogue / battle text** | Not from chat. These codes appear only in game-authored strings. | `\`-escape engine (§5). |
| **Your name colour** | `/namecolor <name>` | One of 11 presets (§2). |

Banned words are replaced with `$%@&` before display, in both `scr_receivechat` and `scr_drawchat`.

---

## 2. `/namecolor` presets and style settings

`/namecolor` (in `gml_Script_scr_commands`) accepts `/namecolor red`, `/namecolor Red` or `/namecolor [red]`. Each
branch stores the colour below as an inline `double` immediate into `namecolor`.

| Command arg | GML constant | BGR | RGB |
|---|---|---|---|
| white | `c_white` | `0xFFFFFF` | `#FFFFFF` |
| red | `c_red` | `0x0000FF` | `#FF0000` |
| yellow | `c_yellow` | `0x00FFFF` | `#FFFF00` |
| green | `c_green` (not lime) | `0x008000` | `#008000` |
| blue | `c_blue` | `0xFF0000` | `#0000FF` |
| orange | `c_orange` | `0x40A0FF` | `#FFA040` |
| purple | `c_purple` | `0x800080` | `#800080` |
| fuchsia | `c_fuchsia` | `0xFF00FF` | `#FF00FF` |
| olive | `c_olive` | `0x008080` | `#808000` |
| teal | `c_teal` | `0x808000` | `#008080` |
| maroon | `c_maroon` | `0x000080` | `#800000` |

`/resetcolor` also exists. Three more `namecolor` writes sit outside the preset block, in a branch that calls
`gms_chat_toggle` and checks `gms_self_name() == "RickyG"` (the developer): `c_lime` (`0x00FF00`) is assigned when the
name matches, and `c_aqua` (`0xFFFF00`) and `c_white` on the other paths. These are a developer/admin name-colour
override, not something a normal player can select. The exact command that reaches this branch is **(unresolved)**.

Related style commands: `/chatstyle 1|2`, `/localstyle 1|2`, `/localopacity` (`/localalpha`) `0 | 0.25 | 0.3 | 0.33 | 0.5 | 0.75`,
`/localfreeze`, `/msglimit 1-3`.

**Settings menu** (`obj_player_Draw_64`). Each label is chosen by comparing a variable to a constant:

| Menu entry | Variable | Values → label |
|---|---|---|
| Local Chat UI | `obj_game.localstyle` | `1` → DEFAULT, `2` → CLASSIC, anything else → SIMPLE |
| Nametag Style | `obj_game.namestyle` | `1` → OUTLINE, `2` → SHADOW, `3` → PLAIN |
| (border option) | `bordersetting` | `2` → SIMPLE, otherwise DYNAMIC or NONE |

The help text describes Local Chat UI as switching between "its default look, a simpler look, and the classic look".
`/localstyle 1|2` writes the same `localstyle` variable.

---

## 3. Global chat rendering (`scr_drawchat`)

`scr_drawchat` has no direct callers. It is registered as the GMS draw-chat callback (`gms_script_set_drawchat`).

**Line format:**

```
[<name>]: <message>        normal user
[<name>]*: <message>       sender has admin rights (gms_other_admin_rights / gms_self_admin_rights)
(This user is blocked.)    replaces messages from blocked users
```

**Drawing.** Every line is drawn with `draw_text_ext_transformed`: first **8 passes in black** (a 1-px outline), then
one pass in the line's colour. Draw alpha is reset to `1.0` at the start.

**Colours passed to the engine's `draw_set_colour`:**

| Value | Use |
|---|---|
| `0x000000` | Outline passes. |
| runtime value | Normal colour: the chat packet's `i32 color` or the sender's name colour. |
| `0xFFFFFF` | Plain white lines. |
| `0xFF00FF` (fuchsia) | Final pass of one `[name]*:` (admin) branch. The selecting condition is **(unresolved)**. |
| `c_rainbow` instance var | Cycling rainbow via `randomize()` and `make_color_hsv(…, 255, 255)`. Used on the branch keyed to the name `"RickyG"`. |
| `0x0000FF` (red) | Single pass after the name-less line group, most likely the "(This user is blocked.)" notice **(inferred)**. |

`gml_Script_gms_chat_draw` (the stock GMS chat UI, not the game's own) escapes `#` to `\#`. In GameMaker 1.x, `#` is a
newline in `draw_text`, so a typed `#` would otherwise break the line.

---

## 4. Local chat history — backtick codes (`scr_veil_drawchat`)

Called only from `obj_rp_localhistory_Draw_64` (the "Room History / Server History" panel, which draws copies held
in `stored_lc_log` / `stored_lc_log_server`; an empty panel shows "(But nobody came...)").

The function walks the string with `string_char_at`. When it meets `` ` ``, it reads the **next character**, applies
`string_lower`, and switches the current colour. Both characters are consumed and not drawn:

| Code | Colour | BGR | RGB |
|---|---|---|---|
| `` `y `` | yellow (`c_yellow`) | `0x00FFFF` | `#FFFF00` |
| `` `c `` | silver (`c_silver`) | `0xC0C0C0` | `#C0C0C0` |
| `` `$ `` | gray (`c_gray`) | `0x808080` | `#808080` |
| `` `& `` | white | `0xFFFFFF` | `#FFFFFF` |
| `` ` `` + anything else | the function's default colour argument | — | — |

- Codes are case-insensitive (`string_lower`). The starting colour is white (`16777215`).
- Word-wrapping uses `string_width`, and the measuring loop skips the two-character codes, so they don't count
  toward line width.
- `#` is skipped by the measuring loop (not counted, not drawn). Whether it also forces a line break when drawing is
  **(unresolved)**.
- Glyphs are drawn one at a time with `draw_text_transformed_colour`.

**User-injectable (inferred).** No code that strips `` ` `` exists on the local-chat path: the only other code using
the `` ` `` literal is `scr_writer` and `obj_glitchtitle_Alarm_2`. So a local message such as ``hi `yTHERE`` would
probably show "THERE" in yellow in the history panel.

### 4.1 How history entries are stored (`scr_receivelocal`)

`scr_receivelocal` takes seven arguments: `(isServer, who, x, message, hh, mm, extra)`. It shifts a **96-row** history
down by one (rows 95 → 0) and writes the new row 0 into `obj_game`:

| Array | Contents |
|---|---|
| `lc_log[row, 0]` (room) / `lc_log_server[row, 0]` (server) | `` "`c" + who + " (" + x + "):`w " + message `` |
| `lc_log[row, 1]` / `lc_log_server[row, 1]` | `"[" + hh + ":" + mm + "] "` (timestamp) |
| `lc_log[row, 2]` / `lc_log_server[row, 2]` | the `extra` argument |
| `lc_log2[row]` / `lc_log_server2[row]` | `sha1_string_unicode(base64_encode(<column 0>))`: an **integrity checksum** of the line, not a second log |

So the name/header shows in **silver**. `` `w `` isn't a defined code, so the message falls back to the **default
colour**. Hours and minutes are zero-padded with `"0"`.

---

## 5. Typewriter `\` escapes (speech bubbles, dialogue box, act/battle text)

These appear in game-authored strings, e.g. ``Will you use [\rMERCY\0],\nor will you [\rFIGHT\0]?``. Three draw
events implement the same engine: `obj_bubble_Draw_0`, `obj_acttext_Draw_0` and `obj_dialogue_Draw_0`. When the
engine meets `\`, it compares the next character against the table below.

Every glyph is drawn at `x + random_range(-intensity, intensity)`, `y + random_range(-intensity, intensity)`, so
`intensity` is a per-writer shake amount (normally 0). Glyphs advance by `gap`; `myColor` is the writer's own default
colour; `t`, `freq` and `amplitude` are instance variables.

### 5.1 Shared escapes

| Escape | Bubble (`obj_bubble`) | Dialogue / act text | Meaning |
|---|---|---|---|
| `\0` | `0` (black) | `0xFFFFFF` (white) | Reset to the base colour. |
| `\s` | black | white | Base colour, with a **fixed ±1 px jitter** (`random_range(-1, 1)`) instead of `intensity`: "shaky" text. |
| `\d` | black | white | Base colour, and sets `diddelay = 1`: the following characters type **slowly** (§5.3). Every other escape resets `diddelay` to 0. |
| `\n` | black | white | **Line break:** resets the x cursor to 0 and increments the line counter (the next line is drawn one line height lower). |
| `\c`, `\1` | `myColor` | `myColor` | Switch to the writer's default colour. |
| `\y` | `0x00FFFF` | `0x00FFFF` | Yellow `#FFFF00`. |
| `\r` | `0x0000FF` | `0x0000FF` | Red `#FF0000`. |
| `\b` | `0xFF0000` | `0xFF0000` | Blue `#0000FF`. |
| `\g` | `make_colour_hsv(t, 255, 255)` | same | Rainbow (hue cycles with `t`). |
| `\2` | rainbow + `sin(…)` with `freq` / `amplitude` / `room_speed` | same | Rainbow **and** wavy. |
| `\i` | `sin` wave, base colour | same, white | Wavy text. |

### 5.2 Dialogue-box-only escapes

`obj_dialogue_Draw_0` checks, in order, `0 - s w h p c r b 1 i g 2 n d P U`, then `u R M F`:

| Escape | Effect |
|---|---|
| `\-` | Like `\0`: resets `diddelay` and continues with the base colour. |
| `\w` | Sets `soundoverride = 1`, then draws with a `0x404040` shadow and white in `myFont`. Where `soundoverride` is read is **(unresolved)**. |
| `\h` | Sets the voice blip `mysound` to sound 262, `snd_nothing` (silent typing). Draws layered: `0x404040` (offset 2) → `0x808080` (offset 1) → white. |
| `\p` | Sets `mysound` to sound 0, `snd_plaintext` (the plain text blip). |
| `\F` | Sets `mysound` to sound 2, `snd_floweytext` (Flowey's voice). |
| `\P` | `audio_pause_all()` |
| `\R` | `audio_resume_all()` |
| `\U` | `audio_pause_sound(182)`: `mus_grillbys` |
| `\u` | `audio_resume_sound(182)`: `mus_grillbys` |
| `\M` | `audio_stop_sound(209)`: `mus_youroldfriend` |

**Dark World.** When `area == "darkworld"`, dialogue glyphs also get a `draw_text_color` shadow pass at alpha `0.75`,
and the box uses `chatbox`.

### 5.3 Typing speed, glyph spacing and newlines

After drawing up to the current character, the writer sets `delay` (frames until the next character) from that
character:

| Character | `delay` |
|---|---|
| `.` `!` `?` | `12.5` |
| `,` | `8` |
| anything else, while `diddelay == 1` (after `\d`) | `9.5` |
| anything else | the writer's `mydelay` |

The dialogue box also pauses on `:` `;` `)` `"`, and uses `slowdot` for runs of `.`.

**Glyph spacing (dialogue box).** Separately from escapes, the dialogue box applies a per-letter offset to some
lower-cased glyphs: `−1` for `l`, `i` and `!`, `−2` for `m` and `−1` for `w`. That makes it kerning for the
proportional font, not markup; that the offset applies to the x advance is **(inferred)**.

**Newlines.** Game strings use the `\n` escape (§5.1). `obj_bubble_Alarm_1` converts `\n` → `#` (with
`string_replace_all`) before measuring with `string_width_ext`, because `#` is the GameMaker 1.x newline. Menu and UI
text uses `#` directly (e.g. `"Are you sure?# # #"`).

### 5.4 Choice prompts (`^` pauses)

`obj_choice_dr_Step_0` types out choice text with its own small parser:

| Sequence | Effect |
|---|---|
| `\` + any char | Skipped as a pair (`i += 2`) and not typed. The escape is applied by the draw event. |
| `^N` (N a digit) | **Pause:** `delay = 1`, `alarm = room_speed · real(N) · 0.25`, so `^4` waits one second. The digit is consumed. |
| space | Typed without the per-character delay. |

---

## 6. Chat-related synced data (cross-ref `PROTOCOL.md`)

- **Chat packet `0x0A`**: `i32 color, str message, str tag`. The colour is the sender's chat colour, not a fixed
  value: `0x00FFFFFF` (white) in `game.pcapng`, `0x007B7B7B` for `user_b` in `game2.pcapng`; received lines carried
  other colours per sender. The `tag` is
  `"localchat"` for local chat.
- **`GMS_Alarm_5`**: chat-history instance variables `name, pid, msg, fnt, color, icon, icnum`. `fnt` and `color`
  travel per message, so the receiving client renders each line with the sender's font index and colour **(inferred)**.
  ✔ `game2.pcapng`: one local line created a one-time instance (object 1571) with `name = "user_b"`,
  `pid = "1234567"`, `msg = "local"`, `fnt = 2`, `color = 8092539` (`0x7B7B7B`, the same colour as the `0x0A`),
  `icon = 1665`, `icnum = 0`. Global chat creates no such instance.
- **Bubbles above players**: player variables `pf_message1..3` and `localchat`.

---

## 7. Open questions

- The condition selecting the fuchsia admin line in `scr_drawchat`, and confirmation that the red pass is the
  blocked-user notice.
- Where `soundoverride` (set by `\w`) is consumed.
- Whether `#` forces a line break in the local-history renderer.
- The command that reaches the `RickyG` / `c_aqua` / `c_lime` name-colour branch.
- Runtime confirmation that typed `` ` `` codes render in local history.
