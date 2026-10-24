--[[
  dfc.lua — Wireshark dissector for DF CONNECTED v2.7.15 (GameMaker Server+ / "XServer" protocol).

  Written from ../../PROTOCOL.md. Decodes live captures and saved files on TCP port 25500:
    * framing: varint length prefix (bit0 = continuation), u16-framed 0x01 handshake  (§3)
    * every C→S and S→C message in §6 / §12, movement (§7), synced instances (§10), P2P (§11)
    * TValue / NVar values, including the per-direction name caches (0x85–0x8A) and the
      player cache (0x8C), so cached variables show their name and player indices show names
  State (caches, roster) is built on the first, in-order pass and memoised per message, so
  re-dissecting a packet later (clicking around in the GUI) shows the values as they were then.

  Install: copy into %APPDATA%\Wireshark\plugins\  (or run:  wireshark -X lua_script:dfc.lua)
  Filters:  dfc  ·  dfc.c2s.id == 0x0a  ·  dfc.chat.msg contains "hi"  ·  dfc.var.name == "myhp"
            dfc.p2p.msg == 4  ·  dfc.player.name == "SomePlayer"  ·  dfc.x > 500
  Captures must include the start of the TCP connection (the caches are defined at login).
]]

local p = Proto("dfc", "DF CONNECTED (GameMaker Server+)")

p.prefs.port         = Pref.uint("TCP port", 25500, "Game server port (both directions are decoded)")
p.prefs.manifest_max = Pref.uint("Manifest entries to list", 300, "Max names shown from the 0x15 resource manifest")
p.prefs.info_max     = Pref.uint("Info column items", 12, "Max message summaries per packet in the Info column")

---------------------------------------------------------------------------------------------------
-- Names
---------------------------------------------------------------------------------------------------
local C2S_NAMES = {
  [0x01]="Handshake", [0x02]="Login", [0x03]="Set player var", [0x06]="Set global var",
  [0x07]="Team score set", [0x08]="Instance create (ext)", [0x09]="Instance destroy", [0x0A]="Chat",
  [0x0B]="Chat mode", [0x0C]="PlayerINI write", [0x0E]="GameINI write", [0x11]="PlayerINI delete",
  [0x12]="GameINI delete", [0x15]="Resource manifest", [0x16]="P2P", [0x17]="Player has account?",
  [0x1A]="Instance create (once)", [0x1B]="Instance create (once,2)", [0x1C]="Instance create (ext,2)",
  [0x1D]="Instance create (full)", [0x1E]="Instance create (full,2)",
  [0x20]="Admin kick", [0x21]="Admin ban", [0x22]="Admin unban", [0x29]="Achievement reached",
  [0x2B]="Highscore add", [0x2D]="Guest highscore", [0x34]="Register account", [0x37]="Statistic set",
  [0x3A]="Friend request", [0x3D]="Instance var", [0x3E]="Instance position", [0x3F]="Instance handover",
  [0x41]="Game version", [0x4B]="BDB open", [0x4C]="BDB open+lock", [0x4D]="BDB close",
  [0x5B]="VS end", [0x5C]="Session create", [0x5D]="Session join", [0x64]="Ping ack",
  [0x85]="Cache def: player vars", [0x86]="Cache def: global vars", [0x87]="Cache def: PlayerINI",
  [0x88]="Cache def: GameINI", [0x89]="Cache def: table 4", [0x8A]="Cache def: table 5",
  [0x8C]="Player-cache def", [0x8F]="Sending policy", [0x90]="Request data update",
  [0x96]="Environment report", [0x97]="Keep-alive", [0x98]="Module-scan reply",
  [0x99]="Trusted transaction", [0x9B]="Auth response", [0xFF]="Logout",
}
local S2C_NAMES = {
  [0x01]="Connection confirmed", [0x02]="Login result", [0x03]="Player var", [0x04]="Legacy position",
  [0x05]="Player presence", [0x06]="Global var", [0x07]="Team score", [0x08]="Instance created (ext)",
  [0x09]="Instance destroyed", [0x0A]="Chat", [0x0C]="PlayerINI value", [0x0D]="PlayerINI error",
  [0x0E]="GameINI value", [0x0F]="GameINI error", [0x10]="Server error", [0x13]="VS ready",
  [0x14]="Resource enumeration", [0x15]="Sound command", [0x16]="P2P", [0x17]="Has-account reply",
  [0x18]="Own player ID", [0x19]="Sync-ID base",
  [0x1A]="Instance created (once)", [0x1B]="Instance created (once,2)", [0x1C]="Instance created (ext,2)",
  [0x1D]="Instance created (full)", [0x1E]="Instance created (full,2)",
  [0x23]="Limits", [0x28]="Achievement def", [0x29]="Achievement reached", [0x2A]="Highscore list",
  [0x2B]="Highscore entry", [0x2C]="Highscore delete", [0x2D]="Guest-highscore result",
  [0x2E]="Friend entry", [0x2F]="Friend online", [0x30]="Friend offline", [0x31]="Own admin rights",
  [0x32]="Logged in as guest", [0x33]="Player admin rights", [0x34]="Registration status",
  [0x35]="Master player", [0x36]="Statistic def", [0x37]="Statistic value", [0x38]="Server clock",
  [0x3A]="Friend-request result", [0x3C]="Data-update result", [0x3D]="Instance var",
  [0x3E]="Instance position", [0x3F]="Instance owner", [0x41]="Update available", [0x42]="No update",
  [0x4B]="BDB data", [0x4C]="BDB lock", [0x50]="Cmd: room_goto", [0x51]="Cmd: room_goto_next",
  [0x52]="Cmd: room_goto_previous", [0x53]="Cmd: room_restart", [0x54]="Cmd: sound stop",
  [0x55]="Cmd: sound_stop_all", [0x5A]="VS time left", [0x5B]="VS ended", [0x5C]="Current session",
  [0x5E]="Session list", [0x61]="(ignored)", [0x62]="(dead feature)", [0x64]="Ping", [0x65]="Ping (high)",
  [0x83]="Username", [0x84]="Geo-location",
  [0x85]="Cache def: player vars", [0x86]="Cache def: global vars", [0x87]="Cache def: PlayerINI",
  [0x88]="Cache def: GameINI", [0x89]="Cache def: table 4", [0x8A]="Cache def: table 5",
  [0x8C]="Player-cache def", [0x90]="Callback", [0x91]="Auth token", [0x98]="Module-scan query",
  [0x99]="Trusted-transaction result", [0x9A]="Trusted-transaction log", [0x9B]="Auth challenge",
  [0xFE]="Fatal error", [0xFF]="Kicked",
}
for id = 0xBE, 0xFD do C2S_NAMES[id] = "Movement"; S2C_NAMES[id] = "Movement" end

local P2P_NAMES = {
  [0]="PvP damage hit", [1]="PvP spare request", [2]="PvP spare/flee/end", [3]="PvP heart action",
  [4]="Direct message", [5]="(no-op)", [6]="Feed: gained LOVE", [7]="Feed: won PvP",
  [8]="Feed: updated status", [9]="Feed: powered up in FFA", [10]="Feed: edited profile",
  [11]="Admin summon to Ruins", [12]="PvP SLOWDOWN", [13]="PvP CONFUSION", [14]="Gold transfer",
  [15]="Feed: new partner", [16]="Feed: posted art", [17]="PvP ready", [18]="Admin/server command",
  [19]="Guild reward share", [20]="Guild: member joined", [21]="Guild: member left",
  [22]="Friend online", [23]="(no-op)", [24]="Guild chat",
}
local LOGIN_ERR = {
  [0]="server not responding", [1]="password required", [2]="account does not exist",
  [3]="wrong password", [4]="server full", [5]="name already logged in", [6]="already logged in",
  [7]="banned from this game", [8]="banned from GameMaker Server", [11]="invalid username characters",
  [12]="username used in highscores", [13]="could not connect", [15]="client unauthenticated (0x9B)",
}
local LOGIN_TYPES  = { [0]="guest", [1]="password", [2]="token" }
local PRESENCE     = { [0]="logged in", [1]="logged out", [2]="joined session", [3]="left session" }
local RES_KINDS    = { [0]="sounds", [1]="objects", [2]="rooms", [3]="scripts", [4]="sprites" }
local SOUND_OPS    = { [0]="play", [1]="loop", [2]="stop" }
local CACHE_TABLES = { [0x85]="player vars", [0x86]="global vars", [0x87]="PlayerINI",
                       [0x88]="GameINI", [0x89]="instance vars?", [0x8A]="data updates?" }
-- Which name-cache table each NVar-carrying message uses (0x89/0x8A are inferred in PROTOCOL.md).
local NVAR_TABLE   = { [0x03]=0x85, [0x06]=0x86, [0x0C]=0x87, [0x0E]=0x88, [0x3D]=0x89, [0x3C]=0x8A,
                       inst=0x89 }

---------------------------------------------------------------------------------------------------
-- Fields and expert info
---------------------------------------------------------------------------------------------------
local f = {
  len        = ProtoField.uint32("dfc.len", "Payload length"),
  from_cli   = ProtoField.bool("dfc.from_client", "From client"),
  c2s_id     = ProtoField.uint8("dfc.c2s.id", "C→S message", base.HEX, C2S_NAMES),
  s2c_id     = ProtoField.uint8("dfc.s2c.id", "S→C message", base.HEX, S2C_NAMES),
  player     = ProtoField.uint8("dfc.player", "Player index"),
  player_nm  = ProtoField.string("dfc.player.name", "Player name"),
  player_id  = ProtoField.uint64("dfc.player.id", "Player ID"),
  username   = ProtoField.string("dfc.username", "Username"),
  chat_color = ProtoField.uint32("dfc.chat.color", "Color (BGR)", base.HEX),
  chat_msg   = ProtoField.string("dfc.chat.msg", "Chat message"),
  chat_tag   = ProtoField.string("dfc.chat.tag", "Chat tag"),
  var_slot   = ProtoField.uint8("dfc.var.slot", "Cache slot"),
  var_type   = ProtoField.uint8("dfc.var.type", "Type byte", base.HEX),
  var_name   = ProtoField.string("dfc.var.name", "Variable"),
  var_value  = ProtoField.string("dfc.var.value", "Value"),
  p2p_msg    = ProtoField.uint8("dfc.p2p.msg", "P2P message", base.DEC, P2P_NAMES),
  p2p_arg    = ProtoField.string("dfc.p2p.arg", "P2P argument"),
  x          = ProtoField.double("dfc.x", "x"),
  y          = ProtoField.double("dfc.y", "y"),
  dir        = ProtoField.double("dfc.direction", "direction"),
  speed      = ProtoField.double("dfc.speed", "speed"),
  sync_id    = ProtoField.uint32("dfc.sync_id", "Sync ID"),
  session    = ProtoField.uint32("dfc.session", "Session ID"),
  string     = ProtoField.string("dfc.string", "String"),
}
p.fields = f

local ef = {
  malformed = ProtoExpert.new("dfc.malformed", "Malformed DFC message", expert.group.MALFORMED, expert.severity.ERROR),
  trailing  = ProtoExpert.new("dfc.trailing", "Trailing bytes after message", expert.group.MALFORMED, expert.severity.WARN),
  unknown   = ProtoExpert.new("dfc.unknown_id", "Unknown message ID", expert.group.UNDECODED, expert.severity.WARN),
  cache     = ProtoExpert.new("dfc.cache_miss", "Name-cache slot not defined earlier (capture started mid-session?)",
                              expert.group.UNDECODED, expert.severity.NOTE),
  framing   = ProtoExpert.new("dfc.framing", "Implausible frame length (stream out of sync?)",
                              expert.group.MALFORMED, expert.severity.ERROR),
}
p.experts = { ef.malformed, ef.trailing, ef.unknown, ef.cache, ef.framing }

local f_stream = Field.new("tcp.stream")

---------------------------------------------------------------------------------------------------
-- Per-stream state + memo (see header)
---------------------------------------------------------------------------------------------------
local streams, memo = {}, {}

local function new_dirstate() return { cache = {}, players = {} } end
local function get_stream(id)
  local st = streams[id]
  if not st then
    st = { c = new_dirstate(), s = new_dirstate(), names_by_id = {}, names_by_sidx = {} }
    streams[id] = st
  end
  return st
end

function p.init()
  streams, memo = {}, {}
end

local Ctx = {}
Ctx.__index = Ctx

-- Runs fn() on the first pass and replays its result afterwards.
function Ctx:memo(fn)
  self.n = self.n + 1
  local k = self.key .. ":" .. self.n
  if not self.visited then
    local v = fn()
    if v == nil then v = false end
    memo[k] = v
    return v
  end
  return memo[k]
end

-- Mutates stream state only on the first pass.
function Ctx:learn(fn) if not self.visited then fn(self.st) end end

-- space "s" = server's player-cache indices, "c" = client's.
function Ctx:player(idx, space)
  local info = self:memo(function()
    local st = self.st
    local id = st[space].players[idx]
    local name = id and st.names_by_id[tostring(id)]
    if not name and space == "s" then name = st.names_by_sidx[idx] end
    return { id = id and tostring(id) or nil, hex = id and id:tohex() or nil, name = name }
  end)
  return info or {}
end

---------------------------------------------------------------------------------------------------
-- Formatting helpers
---------------------------------------------------------------------------------------------------
local function fmtnum(v)
  if type(v) ~= "number" then return tostring(v) end
  if v == math.floor(v) and math.abs(v) < 1e15 then return string.format("%d", v) end
  return string.format("%.10g", v)
end

local function qstr(s, max)
  max = max or 80
  if #s > max then s = s:sub(1, max) .. "…" end
  s = s:gsub('[%c"\\]', function(c)
    if c == '"' then return '\\"' elseif c == '\\' then return '\\\\'
    elseif c == '\n' then return '\\n' else return string.format("\\x%02x", c:byte()) end
  end)
  return '"' .. s .. '"'
end

local function vstr(v, max)
  if type(v) == "string" then return qstr(v, max) end
  return fmtnum(v)
end

local function bgr_to_rgb(c)
  c = c & 0xFFFFFF
  return string.format("#%02X%02X%02X", c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF)
end

local function plabel(idx, info)
  local s = "#" .. idx
  if info.name then s = s .. " " .. info.name end
  return s
end

---------------------------------------------------------------------------------------------------
-- Reader over one message payload; raw reads (r*) never touch the tree, the others add a line.
---------------------------------------------------------------------------------------------------
local Reader = {}
Reader.__index = Reader

local function new_reader(tvb, off, stop, tree)
  return setmetatable({ tvb = tvb, off = off, stop = stop, tree = tree }, Reader)
end

function Reader:left() return self.stop - self.off end
function Reader:take(n)
  if n < 0 or self.off + n > self.stop then
    error(string.format("truncated: need %d byte(s), %d left", n, self.stop - self.off), 0)
  end
  local r = self.tvb(self.off, n)
  self.off = self.off + n
  return r
end
function Reader:since(start)
  if self.off == start then return self.tvb(start, 0) end
  return self.tvb(start, self.off - start)
end

function Reader:ru8()  local r = self:take(1) return r:uint(), r end
function Reader:ru16() local r = self:take(2) return r:le_uint(), r end
function Reader:ru32() local r = self:take(4) return r:le_uint(), r end
function Reader:ri32() local r = self:take(4) return r:le_int(), r end
function Reader:rf32() local r = self:take(4) return r:le_float(), r end
function Reader:rf64() local r = self:take(8) return r:le_float(), r end
function Reader:ru64() local r = self:take(8) return r:le_uint64(), r end
function Reader:ru24be() local r = self:take(3) return r:uint(), r end
function Reader:rstr()
  local s = self.off
  local n = self:ru16()
  local v = ""
  if n > 0 then v = self:take(n):string(ENC_UTF_8) end
  return v, self:since(s)
end
function Reader:rstr8()
  local s = self.off
  local n = self:ru8()
  local v = ""
  if n > 0 then v = self:take(n):string(ENC_UTF_8) end
  return v, self:since(s)
end

local function shower(raw, fmt)
  return function(self, label, field, mapping)
    local v, r = raw(self)
    if field then
      self.tree:add_le(field, r, v)
    else
      local text = fmt(v)
      if mapping and mapping[v] then text = text .. " (" .. mapping[v] .. ")" end
      self.tree:add(r, label .. ": " .. text)
    end
    return v, r
  end
end
Reader.u8  = shower(Reader.ru8,  fmtnum)
Reader.u16 = shower(Reader.ru16, fmtnum)
Reader.u32 = shower(Reader.ru32, fmtnum)
Reader.i32 = shower(Reader.ri32, fmtnum)
Reader.f32 = shower(Reader.rf32, fmtnum)
Reader.f64 = shower(Reader.rf64, fmtnum)
Reader.u64 = shower(Reader.ru64, tostring)
Reader.str = shower(Reader.rstr, function(v) return qstr(v, 200) end)
function Reader:hex32(label)
  local v, r = self:ru32()
  self.tree:add(r, string.format("%s: 0x%08X", label, v))
  return v, r
end
function Reader:rest(label)
  local n = self:left()
  if n == 0 then return end
  local r = self:take(n)
  self.tree:add(r, string.format("%s (%d bytes)", label, n))
  return r
end

---------------------------------------------------------------------------------------------------
-- TValue (§4.1) and NVar (§4.2)
---------------------------------------------------------------------------------------------------
local FIXED_D = { 1, 2, 5 }

-- Reads the payload for type byte t; returns value, short type description.
local function tvalue_payload(r, t)
  if t >= 0x80 then return (t & 0x7F) - 64, "small int" end
  if t == 0x7F then return (r:rf64()), "f64" end
  if t == 0x7E then return (r:rf32()), "f32" end
  if t == 0x7D then return (r:rstr()), "str16" end
  if t == 0x7C then return (r:rstr8()), "str8" end
  if t >= 0x78 then
    local n = t & 7
    if n == 0 then return "", "short str" end
    return r:take(n):string(ENC_UTF_8), "short str"
  end
  local e, n, s = (t >> 3) & 0xF, (t >> 1) & 3, t & 1
  local m = r:take(n + 1):le_uint()
  local D = FIXED_D[e % 3 + 1] * 10 ^ (e // 3)
  local v = m / D
  if s == 1 then v = -v end
  return v, string.format("fixed %dB /%s", n + 1, fmtnum(D))
end

local function read_tvalue(r)
  local s = r.off
  local t = r:ru8()
  local v, desc = tvalue_payload(r, t)
  return v, desc, r:since(s)
end

-- Returns name (or nil if unresolvable), value, display string.
local function read_nvar(r, ctx, tbl, owner)
  local s = r.off
  local slot, slot_r = r:ru8()
  local name, v, desc, t
  if slot == 0 then
    name = r:rstr(); v = r:rstr(); desc = "uncached str"
  elseif slot == 1 then
    name = r:rstr(); v = r:rf64(); desc = "uncached f64"
  else
    local ent = ctx:memo(function()
      local c = ctx.ds.cache[tbl]
      local e = c and c[slot]
      return e and { name = e.name, type = e.type } or false
    end)
    if not ent then
      local it = r.tree:add(r:since(s), string.format("Cached var, slot %d of %s: not defined", slot,
                                                       CACHE_TABLES[tbl] or "?"))
      it:add_proto_expert_info(ef.cache)
      r:take(r:left())      -- value length depends on the unknown type; skip the rest of this message
      return nil, nil, "?"
    end
    name, t = ent.name, ent.type
    v, desc = tvalue_payload(r, t)
    desc = "slot " .. slot .. ", " .. desc
  end
  local rng = r:since(s)
  local full = owner and (owner .. "." .. name) or name
  local disp = vstr(v, 200)
  local sub = r.tree:add(rng, string.format("%s = %s  [%s]", full, disp, desc))
  sub:add(f.var_name, rng, name)
  sub:add(f.var_value, rng, type(v) == "string" and v or fmtnum(v))
  sub:add(f.var_slot, slot_r)
  if t then sub:add(f.var_type, rng, t) end
  return name, v, disp
end

---------------------------------------------------------------------------------------------------
-- Shared sub-decoders
---------------------------------------------------------------------------------------------------
-- 12+12 packed dir/speed (§7.3 mode 3): direction = low12/11, speed = high12/80 − 25.6.
-- The 24 bits are big-endian, like the 12+12 position packing: a standing player is 80 00 00.
local function read_dirspeed24(r)
  local v, rng = r:ru24be()
  local d, sp = (v & 0xFFF) / 11, (v >> 12) / 80 - 25.6
  r.tree:add(f.dir, rng, d)
  r.tree:add(f.speed, rng, sp)
  return d, sp
end
local function read_dirspeed8(r)
  local b, rng = r:ru8()
  local d, sp = (b >> 4) * 22.5, (b & 0xF) - 8
  r.tree:add(f.dir, rng, d)
  r.tree:add(f.speed, rng, sp)
  return d, sp
end

local function add_xy(r, start, x, y)
  local rng = r:since(start)
  if x then r.tree:add(f.x, rng, x) end
  if y then r.tree:add(f.y, rng, y) end
end

-- u8 player (server index space) with name lookup.
local function read_player(r, ctx, label)
  local idx, rng = r:ru8()
  local info = ctx:player(idx, "s")
  local it = r.tree:add(f.player, rng)
  if label then it:prepend_text(label .. " ") end
  if info.name then it:append_text(" (" .. info.name .. ")"); r.tree:add(f.player_nm, rng, info.name) end
  if info.hex then r.tree:add(f.player_id, rng, UInt64.fromhex(info.hex)) end
  return idx, info
end

local function read_player_id(r, ctx, label)
  local id, rng = r:ru64()
  local it = r.tree:add_le(f.player_id, rng)
  if label then it:prepend_text(label .. " ") end
  local name = ctx:memo(function() return ctx.st.names_by_id[tostring(id)] end)
  if name then it:append_text(" (" .. name .. ")"); r.tree:add(f.player_nm, rng, name) end
  return id, name
end

local function nvar_msg(tbl_of)
  return function(r, ctx, id)
    local owner
    if not ctx.c2s and (id == 0x03) then
      local idx, info = read_player(r, ctx)
      owner = plabel(idx, info)
    end
    local name, _, disp = read_nvar(r, ctx, NVAR_TABLE[tbl_of or id], owner)
    return string.format("%s%s = %s", owner and (owner .. ".") or "", name or "?", disp)
  end
end

local function cache_def(r, ctx, id)
  local slot = r:u8("Slot")
  local name = r:str("Name")
  local t = r:u8("Type byte")
  ctx:learn(function()
    local c = ctx.ds.cache[id]
    if not c then c = {}; ctx.ds.cache[id] = c end
    c[slot] = { name = name, type = t }
  end)
  return string.format("Cache[%s] %d = %s/0x%02X", CACHE_TABLES[id], slot, name, t)
end

local function player_cache_def(r, ctx)
  local idx = r:u8("Index")
  local id, rng = r:ru64()
  r.tree:add_le(f.player_id, rng)
  local space = ctx.c2s and "c" or "s"
  ctx:learn(function(st)
    local old = st[space].players[idx]
    st[space].players[idx] = id
    if space == "s" and (not old or tostring(old) ~= tostring(id)) then st.names_by_sidx[idx] = nil end
  end)
  return string.format("Player-cache %d = %s", idx, tostring(id))
end

local function movement(r, ctx, id)
  local who = ""
  if not ctx.c2s then
    local idx, info = read_player(r, ctx)
    who = plabel(idx, info) .. " "
  end
  local fl = id - 0xBE
  local xm, ym, sm = (fl >> 4) & 3, (fl >> 2) & 3, fl & 3
  r.tree:add(r.tvb(r.off - (ctx.c2s and 1 or 2), 1),
             string.format("Flags: 0x%02X (X mode %d, Y mode %d, speed/dir mode %d)", fl, xm, ym, sm))
  local s, x, y = r.off, nil, nil
  if xm == 3 then
    if ym == 0 then
      local b = r:take(3)
      local b0, b1, b2 = b(0, 1):uint(), b(1, 1):uint(), b(2, 1):uint()
      x, y = ((b1 & 0xF) << 8) | b2, (b0 << 4) | (b1 >> 4)
    elseif ym == 1 then x = r:ru8(); y = r:ru8()
    elseif ym == 2 then x = r:ru8() * 2; y = r:ru8() * 2
    else x, y = 0, 0 end
  else
    if xm == 1 then x = r:ru16() elseif xm == 2 then x = r:ri32() end
    if ym == 1 then y = r:ru16() elseif ym == 2 then y = r:ri32() elseif ym == 3 then y = r:ru8() * 2 end
  end
  add_xy(r, s, x, y)
  local d, sp
  if r:left() > 0 then
    if sm == 0 then local b, rng = r:ru8(); d = b / 240 * 360; r.tree:add(f.dir, rng, d)
    elseif sm == 1 then local b, rng = r:ru8(); sp = b / 8 - 16; r.tree:add(f.speed, rng, sp)
    elseif sm == 2 then d, sp = read_dirspeed8(r)
    else d, sp = read_dirspeed24(r) end
  end
  local parts = {}
  if x then parts[#parts + 1] = "x=" .. fmtnum(x) end
  if y then parts[#parts + 1] = "y=" .. fmtnum(y) end
  if d then parts[#parts + 1] = "dir=" .. fmtnum(d) end
  if sp then parts[#parts + 1] = "spd=" .. fmtnum(sp) end
  return "Move " .. who .. table.concat(parts, " ")
end

local INST_KIND = { [0x1A]="one-time", [0x1B]="one-time", [0x08]="extended", [0x1C]="extended",
                    [0x1D]="full", [0x1E]="full" }
local function inst_create(r, ctx, id)
  local kind = INST_KIND[id]
  r.tree:add(r.tvb(r.off - 1, 1), "Kind: " .. kind ..
             ((id == 0x1B or id == 0x1C or id == 0x1E) and " (flag set)" or ""))
  local owner = ""
  if not ctx.c2s then local idx, info = read_player(r, ctx, "Owner"); owner = plabel(idx, info) .. " " end
  local sync
  if kind ~= "one-time" then
    local v, rng = r:ru16()
    sync = v + 1000000
    r.tree:add(f.sync_id, rng, sync)
  end
  local fl, flr = r:ru8()
  r.tree:add(flr, string.format("Flags: 0x%02X", fl))
  local obj
  if fl & 0x08 ~= 0 then obj = r:u32("object_index") else obj = r:u8("object_index") end
  local X, Y = (fl >> 6) & 3, (fl >> 4) & 3
  local s, x, y = r.off, nil, nil
  if X == 3 then
    if Y == 0 then x, y = 0, 0
    elseif Y == 1 then x = r:ru16(); y = x
    elseif Y == 2 then
      local b = r:take(3)
      local b0, b1, b2 = b(0, 1):uint(), b(1, 1):uint(), b(2, 1):uint()
      x, y = ((b1 & 0xF) << 8) | b2, (b0 << 4) | (b1 >> 4)
    else x = r:ri32(); y = r:ri32() end
  else
    if X == 0 then x = r:ru8() elseif X == 1 then x = r:ru8() * 2 else x = r:ru16() end
    if Y == 0 then y = r:ru8() elseif Y == 1 then y = r:ru8() * 2 elseif Y == 2 then y = r:ru16() else y = r:ri32() end
  end
  add_xy(r, s, x, y)
  if fl & 0x04 == 0 then read_dirspeed8(r) else read_dirspeed24(r) end
  local vc = fl & 3
  if vc == 3 then vc = r:u8("Var count") end
  for _ = 1, vc do read_nvar(r, ctx, NVAR_TABLE.inst) end
  return string.format("Instance %s %sobj=%d%s at %s,%s, %d var(s)", kind, owner, obj,
                       sync and (" sync=" .. sync) or "", fmtnum(x), fmtnum(y), vc)
end

local function p2p(r, ctx)
  local idx, rng = r:ru8()
  local info, who
  if ctx.c2s then
    info = ctx:player(idx, "c")
    local it = r.tree:add(f.player, rng)
    it:prepend_text("Target ")
    if info.id == "0" then it:append_text(" (broadcast)") elseif info.name then it:append_text(" (" .. info.name .. ")") end
    who = "→ " .. ((info.id == "0") and "all" or plabel(idx, info))
  else
    info = ctx:player(idx, "s")
    local it = r.tree:add(f.player, rng)
    it:prepend_text("Sender ")
    if info.name then it:append_text(" (" .. info.name .. ")"); r.tree:add(f.player_nm, rng, info.name) end
    who = "from " .. plabel(idx, info)
  end
  local msg = r:u8(nil, f.p2p_msg)
  local argc = r:u8("argc")
  local args = {}
  for i = 0, argc - 1 do
    local v, desc, vr = read_tvalue(r)
    local disp = vstr(v, 200)
    local it = r.tree:add(f.p2p_arg, vr, type(v) == "string" and v or fmtnum(v))
    it:set_text(string.format("arg%d = %s  [%s]", i, disp, desc))
    args[#args + 1] = vstr(v, 40)
  end
  return string.format("P2P %s: %d %s(%s)", who, msg, P2P_NAMES[msg] or "?", table.concat(args, ", "))
end

local function chat(r, ctx)
  local who = ""
  if not ctx.c2s then local idx, info = read_player(r, ctx); who = plabel(idx, info) .. ": " end
  local col, cr = r:ri32()
  r.tree:add(f.chat_color, cr, col & 0xFFFFFFFF):append_text(" (RGB " .. bgr_to_rgb(col) .. ")")
  local msg, mr = r:rstr();  r.tree:add(f.chat_msg, mr, msg)
  local tag, tr = r:rstr();  r.tree:add(f.chat_tag, tr, tag)
  return string.format("Chat [%s] %s%s", tag ~= "" and tag or "global", who, qstr(msg, 60))
end

local function scan_list(r)
  local n = r:u32("Entries")
  for _ = 1, n do
    local s = r.off
    local fn, sha = r:rstr(), r:rstr()
    r.tree:add(r:since(s), fn .. "  sha1=" .. sha)
  end
  return n
end

local function inflate(rng, name)
  local ok, t = pcall(function()
    if rng.uncompress_zlib then return rng:uncompress_zlib(name) end
    return rng:uncompress(name)
  end)
  if ok then return t end
end

---------------------------------------------------------------------------------------------------
-- Client → server handlers. Each returns a one-line summary (falls back to the message name).
---------------------------------------------------------------------------------------------------
local C2S = {}

C2S[0x01] = function(r)
  local ver = r:f64("GMS+ client version")
  r:u8("(zero)")
  r:f64("App identifier")
  for i = 1, 4 do r:f64("Magic " .. i) end
  local env = r:hex32("Env flags")
  for i = 1, 4 do r:str("HW id " .. i) end
  return string.format("Handshake (GMS+ %s, env 0x%X)", fmtnum(ver), env)
end
C2S[0x02] = function(r)
  local t = r:u8("Login type", nil, LOGIN_TYPES)
  local user, ur = r:rstr(); r.tree:add(f.username, ur, user)
  if t == 1 then r:str("Hash1 SHA-512(pw+SALT1)"); r:u8("Password length"); r:str("Hash2 SHA-512(pw+user+SALT2)")
  elseif t == 2 then r:str("Login token") end
  return string.format("Login %s (%s)", qstr(user), LOGIN_TYPES[t] or t)
end
C2S[0x03] = nvar_msg()
C2S[0x06] = nvar_msg()
C2S[0x07] = function(r) local t = r:u8("Team"); local s = r:f32("Score"); return "Team " .. t .. " score = " .. fmtnum(s) end
for _, id in ipairs({ 0x08, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E }) do C2S[id] = inst_create end
C2S[0x09] = function(r) local v, rng = r:ru16(); r.tree:add(f.sync_id, rng, v + 1000000); return "Instance destroy " .. (v + 1000000) end
C2S[0x0A] = chat
C2S[0x0B] = function(r) return "Chat mode " .. r:u8("Mode") end
C2S[0x0C] = nvar_msg()
C2S[0x0E] = nvar_msg()
C2S[0x11] = function(r) return "PlayerINI delete " .. qstr((r:str("Key"))) end
C2S[0x12] = function(r) return "GameINI delete " .. qstr((r:str("Key"))) end
C2S[0x15] = function(r, ctx)
  local zr = r:take(r:left())
  local zt = r.tree:add(zr, string.format("zlib data (%d bytes)", zr:len()))
  local u = inflate(zr, "Resource manifest")
  if not u then zt:append_text(" — could not inflate"); return "Resource manifest (zlib)" end
  local off, n, max = 0, 0, p.prefs.manifest_max
  local list = zt:add(u(), string.format("Inflated: %d bytes", u:len()))
  while off < u:len() do
    local l = u(off, 1):uint()
    if off + 1 + l > u:len() then list:add(u(off), "truncated entry"); break end
    if n < max then
      list:add(u(off, 1 + l), string.format("[%d] %s", n, l > 0 and u(off + 1, l):string() or ""))
    end
    off, n = off + 1 + l, n + 1
  end
  list:append_text(string.format(", %d names%s", n, n > max and (" (first " .. max .. " listed)") or ""))
  return string.format("Resource manifest (%d names, %d→%d bytes)", n, zr:len(), u:len())
end
C2S[0x16] = p2p
C2S[0x17] = function(r) return "Has account? " .. qstr((r:str("Name"))) end
C2S[0x20] = function(r, ctx) local idx, info = read_player(r, ctx); local why = r:str("Reason"); return "Admin kick " .. plabel(idx, info) .. " " .. qstr(why) end
C2S[0x21] = function(r, ctx) local idx, info = read_player(r, ctx); r:str("Reason"); local d = r:u32("Duration"); return "Admin ban " .. plabel(idx, info) .. " for " .. d end
C2S[0x22] = function(r) return "Admin unban " .. qstr((r:str("Name"))) end
C2S[0x29] = function(r) return "Achievement reached " .. r:u32("Achievement ID") end
C2S[0x2B] = function(r) local l = r:u32("List ID"); local s = r:f64("Score"); r:u8("Replace"); return "Highscore list " .. l .. " += " .. fmtnum(s) end
C2S[0x2D] = function(r) local n = r:str("Name"); local s = r:f64("Score"); r:u8("(zero)"); return "Guest highscore " .. qstr(n) .. " " .. fmtnum(s) end
C2S[0x34] = function(r) for i = 1, 4 do r:str("Field " .. i) end end
C2S[0x37] = function(r) local id = r:u32("Statistic ID"); local v = r:f64("Value"); return "Statistic " .. id .. " = " .. fmtnum(v) end
C2S[0x3A] = function(r) return "Friend request " .. qstr((r:str("Name"))) end
C2S[0x3D] = function(r, ctx)
  local v, rng = r:ru16(); r.tree:add(f.sync_id, rng, v + 1000000)
  local name, _, disp = read_nvar(r, ctx, NVAR_TABLE[0x3D])
  return string.format("Instance %d.%s = %s", v + 1000000, name or "?", disp)
end
C2S[0x3E] = function(r)
  local v, rng = r:ru16(); r.tree:add(f.sync_id, rng, v + 1000000)
  local s = r.off; local x, y = r:ri32(), r:ri32(); add_xy(r, s, x, y)
  read_dirspeed24(r)
  return string.format("Instance %d at %d,%d", v + 1000000, x, y)
end
C2S[0x3F] = function(r) local v = r:u16("Sync ID (raw)"); return "Instance handover " .. v end
C2S[0x41] = function(r) return "Game version " .. fmtnum(r:f64("Version")) end
C2S[0x4B] = function(r) return "BDB open " .. r:u32("DB ID") end
C2S[0x4C] = function(r) return "BDB open+lock " .. r:u32("DB ID") end
C2S[0x4D] = function(r) r:rest("Blob") end
C2S[0x5C] = function(r) local t = r:u8("Type"); local tag = r:str("Tag"); return "Session create type " .. t .. " " .. qstr(tag) end
C2S[0x5D] = function(r) local v, rng = r:ru16(); r.tree:add(f.session, rng, v); return "Session join " .. v end
for id = 0x85, 0x8A do C2S[id] = cache_def end
C2S[0x8C] = player_cache_def
C2S[0x8F] = function(r) local i = r:u32("Index"); local pol = r:u8("Policy"); return "Sending policy " .. i .. "=" .. pol end
C2S[0x90] = function(r) r:u32("Arg 1"); r:u32("Arg 2"); r:u32("Arg 3"); r:str("Arg 4") end
C2S[0x96] = function(r)
  local env = r:hex32("Env flags")
  local n = 0
  if env ~= 0 and r:left() > 0 then n = scan_list(r) end
  return string.format("Env report 0x%X%s", env, n > 0 and (", " .. n .. " module(s)") or "")
end
C2S[0x98] = function(r)
  local found = r:u8("Found")
  local n = 0
  if found ~= 0 then n = scan_list(r) end
  return "Module-scan reply found=" .. found .. (n > 0 and (", " .. n .. " module(s)") or "")
end
C2S[0x99] = function(r)
  local tid = r:u8("Transaction ID")
  local argc = r:u8("argc")
  for i = 0, argc - 1 do local v, desc, vr = read_tvalue(r); r.tree:add(vr, string.format("arg%d = %s  [%s]", i, vstr(v, 200), desc)) end
  return "Trusted transaction " .. tid .. " (" .. argc .. " args)"
end
C2S[0x9B] = function(r) local s = r:str("Response hex(SHA-512(challenge ∥ secret))"); return "Auth response (" .. #s .. " chars)" end
for _, id in ipairs({ 0x5B, 0x64, 0x97, 0xFF }) do C2S[id] = function() end end

---------------------------------------------------------------------------------------------------
-- Server → client handlers
---------------------------------------------------------------------------------------------------
local S2C = {}

S2C[0x01] = function(r) return "Connection confirmed, id " .. r:u32("Identifier") end
S2C[0x02] = function(r)
  local status = r:u8("Status")
  if status == 1 then
    if r:left() > 0 then r:str("Login token") end
    return "Login OK"
  end
  local code
  if r:left() > 0 then code = r:u8("Error code", nil, LOGIN_ERR) end
  if r:left() > 0 then r:str("Message") end
  return string.format("Login FAILED status=%d%s", status,
                       code and string.format(" err=%d (%s)", code, LOGIN_ERR[code] or "?") or "")
end
S2C[0x03] = nvar_msg()
S2C[0x04] = function(r, ctx)
  local idx, info = read_player(r, ctx)
  local s = r.off; local x, y = r:ri32(), r:ri32(); add_xy(r, s, x, y)
  read_dirspeed24(r)
  return string.format("Legacy pos %s %d,%d", plabel(idx, info), x, y)
end
S2C[0x05] = function(r, ctx)
  local st = r:u8("Status", nil, PRESENCE)
  local idx, info = read_player(r, ctx)
  local name
  if st == 0 or st == 2 then
    local nr; name, nr = r:rstr(); r.tree:add(f.player_nm, nr, name)
    ctx:learn(function(s)
      s.names_by_sidx[idx] = name
      local id = s.s.players[idx]
      if id then s.names_by_id[tostring(id)] = name end
    end)
  end
  return string.format("Presence #%d %s %s", idx, name or info.name or "", PRESENCE[st] or ("status " .. st))
end
S2C[0x06] = nvar_msg()
S2C[0x07] = function(r) local t = r:u8("Team"); local s = r:f32("Score"); return "Team " .. t .. " score = " .. fmtnum(s) end
for _, id in ipairs({ 0x08, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E }) do S2C[id] = inst_create end
S2C[0x09] = C2S[0x09]
S2C[0x0A] = chat
S2C[0x0C] = nvar_msg()
S2C[0x0E] = nvar_msg()
S2C[0x10] = function(r) return "Server error " .. qstr((r:str("Message"))) end
S2C[0x14] = function(r) local k = r:u8("Kind", nil, RES_KINDS); return "Enumerate " .. (RES_KINDS[k] or k) end
S2C[0x15] = function(r) local i = r:u32("Sound index"); local op = r:u8("Op", nil, SOUND_OPS); return "Sound " .. i .. " " .. (SOUND_OPS[op] or op) end
S2C[0x16] = p2p
S2C[0x17] = function(r) local n = r:str("Name"); local v = r:u32("Result"); return "Has account " .. qstr(n) .. " = " .. v end
S2C[0x18] = function(r, ctx)
  local id = read_player_id(r, ctx, "Own")
  ctx:learn(function(s) if s.own_name then s.names_by_id[tostring(id)] = s.own_name end end)
  return "Own player ID " .. tostring(id)
end
S2C[0x19] = function(r) local b = r:u16("Base"); r:u16("(ignored)"); return "Sync-ID base " .. b end
S2C[0x23] = function(r) local a, b, c = r:u32("maxGameINI"), r:u32("maxPlayerINI"), r:u32("numGameLogins"); return string.format("Limits GameINI=%d PlayerINI=%d logins=%d", a, b, c) end
S2C[0x28] = function(r) local id = r:u32("ID"); local n = r:str("Name"); r:str("Description"); return "Achievement " .. id .. " " .. qstr(n) end
S2C[0x29] = function(r) return "Achievement reached " .. r:u32("ID") end
S2C[0x2A] = function(r) local id = r:u32("List ID"); local t = r:str("Title"); return "Highscore list " .. id .. " " .. qstr(t) end
S2C[0x2B] = function(r) local l = r:u32("List ID"); local n = r:str("Name"); local s = r:f64("Score"); return string.format("Highscore [%d] %s %s", l, qstr(n, 30), fmtnum(s)) end
S2C[0x2C] = function(r) return "Highscore delete " .. r:u32("ID") end
S2C[0x2D] = function(r) return "Guest-highscore result " .. r:u8("Result") end
S2C[0x2E] = function(r, ctx)
  local id = read_player_id(r, ctx)
  local name, nr = r:rstr(); r.tree:add(f.player_nm, nr, name)
  ctx:learn(function(s) s.names_by_id[tostring(id)] = s.names_by_id[tostring(id)] or name end)
  return "Friend " .. qstr(name)
end
S2C[0x2F] = function(r, ctx) local id, n = read_player_id(r, ctx); return "Friend online " .. (n or tostring(id)) end
S2C[0x30] = function(r, ctx) local id, n = read_player_id(r, ctx); return "Friend offline " .. (n or tostring(id)) end
S2C[0x31] = function(r) return "Own admin rights " .. r:u8("Rights") end
S2C[0x33] = function(r, ctx) local idx, info = read_player(r, ctx); local v = r:u8("Rights"); return "Admin rights " .. plabel(idx, info) .. " = " .. v end
S2C[0x34] = function(r) return "Registration status " .. r:u8("Status") end
S2C[0x35] = function(r, ctx) local idx, info = read_player(r, ctx); return "Master " .. plabel(idx, info) end
S2C[0x36] = function(r) local id = r:u32("ID"); local n = r:str("Name"); r:str("Description"); return "Statistic " .. id .. " " .. qstr(n) end
S2C[0x37] = function(r) local id = r:u32("ID"); local v = r:f64("Value"); return "Statistic " .. id .. " = " .. fmtnum(v) end
S2C[0x38] = function(r)
  local v, rng = r:ru32()
  local it = r.tree:add(rng, "Seconds: " .. v)
  if v > 1e9 then it:append_text(" (" .. os.date("!%Y-%m-%d %H:%M:%S UTC", v) .. ")") end
  return "Server clock " .. v
end
S2C[0x3A] = function(r) return "Friend-request result " .. r:u8("Result") end
S2C[0x3C] = nvar_msg()
S2C[0x3D] = C2S[0x3D]
S2C[0x3E] = C2S[0x3E]
S2C[0x3F] = function(r, ctx) local v, rng = r:ru16(); r.tree:add(f.sync_id, rng, v + 1000000); local idx, info = read_player(r, ctx, "Owner"); return "Instance " .. (v + 1000000) .. " owner " .. plabel(idx, info) end
S2C[0x41] = function(r) return "Update available " .. qstr((r:str("URL"))) end
S2C[0x4B] = function(r)
  local q = r:u32("Request")
  local n = r:u32("Length")
  if n > 0 then r.tree:add(r:take(n), string.format("Blob (%d bytes)", n)) end
  return "BDB data req " .. q .. " (" .. n .. " bytes)"
end
S2C[0x4C] = function(r) local q = r:u32("Request"); local l = r:u8("Locked"); return "BDB lock req " .. q .. " = " .. l end
S2C[0x50] = function(r) return "room_goto " .. r:u32("Room") end
S2C[0x54] = function(r) return "Sound stop " .. r:u32("Sound index") end
S2C[0x5A] = function(r) return "VS time left " .. r:u32("Time") end
S2C[0x5C] = function(r) local v, rng = r:ru16(); r.tree:add(f.session, rng, v); return "Current session " .. v end
S2C[0x5E] = function(r)
  local n = r:u8("Sessions")
  local parts = {}
  for _ = 1, n do
    local s = r.off
    local id, t, pl, tag = r:ru32(), r:ru8(), r:ru8(), r:rstr()
    local rng = r:since(s)
    r.tree:add(rng, string.format("Session %d: type %d, %d player(s), tag %s", id, t, pl, qstr(tag))):add(f.session, rng, id)
    parts[#parts + 1] = id .. ":" .. pl
  end
  return "Session list (" .. table.concat(parts, " ") .. ")"
end
S2C[0x61] = function(r) r:u32("Value 1"); r:u32("Value 2") end
S2C[0x62] = function(r) local id = r:u32("ID"); local ip = r:str("IP"); return "(dead) " .. id .. " " .. ip end
S2C[0x64] = function(r) local b = r:u8("RTT/3"); r.tree:add(r.tvb(r.off - 1, 1), "Ping: " .. 3 * b .. " ms"); return "Ping " .. 3 * b .. " ms" end
S2C[0x65] = function(r) local b = r:u8("(RTT-765)/3"); return "Ping " .. (765 + 3 * b) .. " ms" end
S2C[0x83] = function(r, ctx)
  local u, ur = r:rstr(); r.tree:add(f.username, ur, u)
  ctx:learn(function(s) s.own_name = u end)   -- bound to an ID by 0x18 (index 0 is not necessarily us)
  return "Username " .. qstr(u)
end
S2C[0x84] = function(r) local iso = r:u32("ISO code"); local c = r:str("Country"); r:str("Country code"); r:str("Languages"); return "Geo " .. c .. " (" .. iso .. ")" end
for id = 0x85, 0x8A do S2C[id] = cache_def end
S2C[0x8C] = player_cache_def
S2C[0x90] = function(r) return "Callback " .. r:u32("Value") end
S2C[0x91] = function(r) local s = r:str("Auth token"); return "Auth token (" .. #s .. " chars)" end
S2C[0x98] = function(r) return "Module-scan query " .. qstr((r:str("Query"))) end
S2C[0x99] = function(r)
  r:u8("Transaction ID")
  local ok = r:u8("OK")
  if ok == 1 and r:left() > 0 then local v, desc, vr = read_tvalue(r); r.tree:add(vr, "Result = " .. vstr(v, 200) .. "  [" .. desc .. "]") end
  return "Trusted-transaction result ok=" .. ok
end
S2C[0x9A] = function(r) return "Trusted-transaction log " .. qstr((r:str("Log"))) end
S2C[0x9B] = function(r) local s = r:str("Challenge (base64)"); return "Auth challenge (" .. #s .. " chars)" end
S2C[0xFE] = function(r) return "FATAL " .. qstr((r:str("Message"))) end
S2C[0xFF] = function(r) local s = r:u8("Status"); local m = r:str("Message"); return "KICKED (" .. s .. ") " .. qstr(m) end
for _, id in ipairs({ 0x0D, 0x0F, 0x13, 0x32, 0x42, 0x51, 0x52, 0x53, 0x55, 0x5B }) do S2C[id] = function() end end

for id = 0xBE, 0xFD do C2S[id] = movement; S2C[id] = movement end

---------------------------------------------------------------------------------------------------
-- Framing and main dissector
---------------------------------------------------------------------------------------------------
local MAX_FRAME = 4 * 1024 * 1024

-- §3.2: the first client message is u16-framed. Recognised by ID 0x01 + a sane f64 version.
local function is_handshake(tvb, off, len)
  if len - off < 11 then return false end
  if tvb(off + 2, 1):uint() ~= 0x01 then return false end
  local L = tvb(off, 2):le_uint()
  if L < 60 or L > 8192 then return false end
  local ver = tvb(off + 3, 8):le_float()
  return ver > 0.5 and ver < 100
end

local function dissect_msg(tvb, hdr_off, hdr_len, plen, tree, ctx)
  local off = hdr_off + hdr_len
  local id = tvb(off, 1):uint()
  local names = ctx.c2s and C2S_NAMES or S2C_NAMES
  local handlers = ctx.c2s and C2S or S2C
  local arrow = ctx.c2s and "C→S" or "S→C"
  local sub = tree:add(p, tvb(hdr_off, hdr_len + plen))
  sub:add(f.len, tvb(hdr_off, hdr_len), plen)
  sub:add(f.from_cli, tvb(hdr_off, hdr_len), ctx.c2s)
  sub:add(ctx.c2s and f.c2s_id or f.s2c_id, tvb(off, 1))
  local r = new_reader(tvb, off + 1, off + plen, sub)
  local name = names[id] or string.format("Unknown 0x%02X", id)
  local h = handlers[id]
  local summary
  if not h then
    sub:add_proto_expert_info(ef.unknown)
    r:rest("Payload")
    summary = name
  else
    local ok, res = pcall(h, r, ctx, id)
    if ok then
      summary = res or name
      if r:left() > 0 then
        sub:add(r.tvb(r.off, r:left()), string.format("Trailing bytes (%d)", r:left()))
           :add_proto_expert_info(ef.trailing)
      end
    else
      sub:add_proto_expert_info(ef.malformed, tostring(res))
      summary = name .. " [malformed]"
    end
  end
  sub:set_text(string.format("DFC %s 0x%02X %s", arrow, id, summary))
  return summary
end

local function info_join(list, max)
  local out, last, count = {}, nil, 0
  local function flush()
    if last then out[#out + 1] = count > 1 and (last .. " ×" .. count) or last end
  end
  for _, s in ipairs(list) do
    if s == last then count = count + 1 else flush(); last, count = s, 1 end
  end
  flush()
  if #out > max then
    local extra = #out - max
    for i = #out, max + 1, -1 do out[i] = nil end
    out[#out + 1] = "+" .. extra .. " more"
  end
  return table.concat(out, ", ")
end

function p.dissector(tvb, pinfo, tree)
  local len = tvb:len()
  if len == 0 then return 0 end
  pinfo.cols.protocol = "DFC"
  local c2s = pinfo.dst_port == p.prefs.port
  local sfield = f_stream()
  local st = get_stream(sfield and sfield() or 0)
  local root = tree:add(p, tvb())
  local off, summaries, n = 0, {}, 0

  while off < len do
    local hdr, plen
    if c2s and off == 0 and is_handshake(tvb, off, len) then
      hdr, plen = 2, tvb(off, 2):le_uint()
    else
      local v, sh, i, done = 0, 0, off, false
      while i < len and i - off < 4 do
        local b = tvb(i, 1):uint()
        i = i + 1
        v = v | ((b >> 1) << sh)
        sh = sh + 7
        if b & 1 == 0 then done = true; break end
      end
      if not done then
        if i - off >= 4 then
          root:add_proto_expert_info(ef.framing); return len
        end
        pinfo.desegment_offset = off
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        break
      end
      hdr, plen = i - off, v
    end
    if plen > MAX_FRAME then root:add_proto_expert_info(ef.framing); break end
    if off + hdr + plen > len then
      pinfo.desegment_offset = off
      pinfo.desegment_len = off + hdr + plen - len
      break
    end
    if plen > 0 then
      local ctx = setmetatable({
        st = st, c2s = c2s, ds = c2s and st.c or st.s, visited = pinfo.visited, n = 0,
        key = pinfo.number .. ":" .. len .. ":" .. off,
      }, Ctx)
      summaries[#summaries + 1] = dissect_msg(tvb, off, hdr, plen, root, ctx)
      n = n + 1
    end
    off = off + hdr + plen
  end

  root:set_len(math.max(off, 1))
  root:append_text(string.format(", %s, %d message(s)", c2s and "client → server" or "server → client", n))
  if n > 0 then
    local prefix = c2s and "C→S " or "S→C "
    local text = info_join(summaries, p.prefs.info_max)
    local cur = tostring(pinfo.cols.info)
    if cur:sub(1, #prefix) == prefix then pinfo.cols.info:append(", " .. text)
    else pinfo.cols.info:set(prefix .. text) end
  end
  return len
end

local tcp_port = DissectorTable.get("tcp.port")
local registered_port = p.prefs.port
tcp_port:add(registered_port, p)

function p.prefs_changed()
  if registered_port ~= p.prefs.port then
    tcp_port:remove(registered_port, p)
    registered_port = p.prefs.port
    tcp_port:add(registered_port, p)
  end
end
