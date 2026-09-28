-- Uploader backend (content_by_lua_file), deployed by deploy/roles/uploader.
--   POST   /up            create, Upload-Length required, Upload-Ext optional -> 201 {"id"}
--   HEAD   /up/<id>       bytes held                                -> 200 Upload-Offset
--   PATCH  /up/<id>       append at Upload-Offset                   -> 204 Upload-Offset | 409 Upload-Offset
--   POST   /up/<id>/done  size == declared, age magic, store, notify -> 200 {"id","size"} | 409 | 400
--   DELETE /up/<id>       drop the partial                          -> 204
--   POST   /up/form       no-JavaScript multipart path              -> 303 done.html | error.html
-- State is the filesystem: <base>/tmp/<id> (partial; its size is the offset), <id>.len
-- ("<declared total> <ext>"), <base>/<id>[.<ext>].age (finished; ext is the plaintext's). nginx spools bodies to disk first, Lua only
-- copies file to file. Check+append and check+rename run under a per-id lock: after a stall
-- abort the old body may still be arriving while the client resumes.
package.path = ngx.var.app_dir .. "/?.lua;" .. package.path
local cfg = require("upload_config")
local cjson = require("cjson.safe")
local ffi = require("ffi")

-- nginx workers run with umask 0; keep created files 0640.
ffi.cdef [[ unsigned int umask(unsigned int mask); ]]
ffi.C.umask(tonumber("027", 8))

local TMP = cfg.base .. "/tmp/"
local locks = ngx.shared.upload_locks
local AGE_MAGIC = { "age-encryption.org/v1", "-----BEGIN AGE ENCRYPTED FILE-----" }

-- No ngx.exit(): callers `return say(...)` and the handler ends normally.
local function say(status, body, headers)
  ngx.status = status
  ngx.header["Cache-Control"] = "no-store"
  for k, v in pairs(headers or {}) do ngx.header[k] = v end
  if body then
    ngx.header["Content-Type"] = "application/json"
    ngx.print(cjson.encode(body))
  end
end

local function size_of(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local n = f:seek("end")
  f:close()
  return n
end

local function read_all(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local s = f:read("*a")
  f:close()
  return s
end

local function write(path, s)
  local f = assert(io.open(path, "wb"))
  f:write(s)
  f:close()
end

local function remove(id)
  os.remove(TMP .. id)
  os.remove(TMP .. id .. ".len")
end

-- The only characters allowed in a stored extension: ASCII letters and digits, 1-8 of them.
-- Everything that becomes part of a filesystem path goes through here or is 32 hex digits
-- from the URL regex below, so no user-controlled slash, dot or NUL can reach a path.
local function safe_ext(ext)
  ext = (ext or ""):lower()
  return (#ext > 0 and #ext <= 8 and ext:match("^[a-z0-9]+$")) and ext or ""
end

-- Extension as the uploader named it ("report.pdf.age" and "report.pdf" both give "pdf").
local function clean_ext(name)
  return safe_ext((name or ""):gsub("%.[Aa][Gg][Ee]$", ""):match("%.([A-Za-z0-9]+)$"))
end

-- The .len sidecar: declared total and the plaintext's extension ("" if none). Written by
-- us, still re-validated on the way back.
local function meta(id)
  local s = read_all(TMP .. id .. ".len")
  if not s then return nil end
  local declared, ext = s:match("^(%d+) ?([^\n]*)")
  return tonumber(declared), safe_ext(ext)
end

local function final_name(id, ext)
  return id .. (ext ~= "" and ("." .. ext) or "") .. ".age"
end

local function rand_id()
  local f = assert(io.open("/dev/urandom", "rb"))
  local b = f:read(16)
  f:close()
  return (b:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

-- Per-id mutex: shared-dict add() is atomic and fails while the key exists; the TTL covers a dead worker.
local function with_lock(id, fn)
  local deadline = ngx.now() + 30
  while not locks:add(id, true, 60) do
    if ngx.now() > deadline then return say(503, { error = "busy" }) end
    ngx.sleep(0.005)
  end
  local ok, err = pcall(fn)
  locks:delete(id)
  if not ok then
    ngx.log(ngx.ERR, "upload: ", err)
    return say(500)
  end
end

-- Signed, expiring download URL for the notification. nginx secure_link checks the same
-- md5(expiry/dl/id secret) in base64url; the uploader knows the id but not the secret.
local function download_link(name)
  if not cfg.link_secret then return "" end
  local e = ngx.time() + cfg.link_days * 86400
  local k = ngx.encode_base64(ngx.md5_bin(e .. "/dl/" .. name .. " " .. cfg.link_secret))
  k = k:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
  return string.format("\nhttps://%s/dl/%s?k=%s&e=%d", cfg.domain, name, k, e)
end

-- Telegram via the internal /_tg proxy (the token lives there), one message per chat id.
-- Best effort: failures are only logged.
local function notify(name, size)
  local text = string.format("%s: nuovo file %s (%.1f MiB)%s", cfg.domain, name, size / 1048576, download_link(name))
  for _, chat in ipairs(cfg.telegram_chat_ids or {}) do
    local res = ngx.location.capture("/_tg", {
      method = ngx.HTTP_POST,
      body = cjson.encode({ chat_id = chat, text = text }),
    })
    if res.status ~= 200 then ngx.log(ngx.ERR, "upload: telegram ", chat, " ", res.status, " ", res.body) end
  end
end

-- Answer to the no-JavaScript form: a redirect to a static page (every HTML must be fixed at
-- signing time for WEBCAT), the id travelling in the query string.
local function page(_, class, id)
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["Location"] = class == "ok" and ("/done.html?id=" .. id) or ("/error.html?reason=" .. class)
  ngx.status = 303
end

-- Store [from, to) of the spooled body as a finished upload: magic check, size cap, notify.
local function store_range(body, from, to, ext)
  local size = to - from
  if size > cfg.max_bytes then return page(413, "big") end
  local src = assert(io.open(body, "rb"))
  src:seek("set", from)
  local head = src:read(40) or ""
  local is_age = false
  for _, magic in ipairs(AGE_MAGIC) do
    if head:sub(1, #magic) == magic then is_age = true end
  end
  if not is_age then src:close(); return page(400, "err") end
  src:seek("set", from)
  local id = rand_id()
  local dst = assert(io.open(TMP .. id, "wb"))
  local left = size
  while left > 0 do
    local chunk = src:read(math.min(left, 1048576))
    if not chunk then break end
    dst:write(chunk)
    left = left - #chunk
  end
  src:close()
  dst:close()
  local name = final_name(id, ext)
  assert(os.rename(TMP .. id, cfg.base .. "/" .. name))
  notify(name, size)
  return page(200, "ok", id)
end

-- ---- routing ---------------------------------------------------------------------
local method = ngx.req.get_method()

-- No-JavaScript path: one multipart POST, file part last (the form puts the checkbox first).
-- Find the end of the file part's headers and the closing boundary; store what lies between.
if ngx.var.uri == "/up/form" then
  if method ~= "POST" then return say(405) end
  local boundary = (ngx.var.content_type or ""):match('boundary="?([^";]+)"?')
  ngx.req.read_body()
  local body = ngx.req.get_body_file()
  if not boundary or not body then return page(400, "err") end
  local f = assert(io.open(body, "rb"))
  local total = f:seek("end")
  f:seek("set", 0)
  local head = f:read(65536) or ""
  local tail_len = math.min(total, 4096)
  f:seek("set", total - tail_len)
  local tail = f:read(tail_len) or ""
  f:close()
  local fpos = head:find("filename=", 1, true)
  local hend -- end of the file part's headers (`and` would truncate find()'s two returns)
  if fpos then _, hend = head:find("\r\n\r\n", fpos, true) end
  local tpos = tail:find("\r\n--" .. boundary .. "--", 1, true)
  if not hend or not tpos then return page(400, "err") end
  local ext = clean_ext(head:match('filename="([^"]*)"', fpos))
  return store_range(body, hend, total - tail_len + tpos - 1, ext)
end

if ngx.var.uri == "/up" then
  if method ~= "POST" then return say(405) end
  local length = tonumber(ngx.var.http_upload_length)
  if not length or length <= 0 or length % 1 ~= 0 then return say(400, { error = "Upload-Length required" }) end
  if length > cfg.max_bytes then return say(413) end
  local id = rand_id()
  write(TMP .. id, "")
  write(TMP .. id .. ".len", length .. " " .. clean_ext("x." .. (ngx.var.http_upload_ext or "")))
  return say(201, { id = id })
end

local m = ngx.re.match(ngx.var.uri, [[^/up/([a-f0-9]{32})(/done)?$]], "jo")
if not m then return say(404) end
local id, finalize = m[1], m[2]
local part = TMP .. id

if finalize then
  if method ~= "POST" then return say(405) end
  return with_lock(id, function()
    local size = size_of(part)
    local declared, ext = meta(id)
    if not size or not declared then return say(404) end
    if size ~= declared then return say(409, { error = "incomplete" }, { ["Upload-Offset"] = size }) end
    local f = io.open(part, "rb")
    local head = f:read(40) or ""
    f:close()
    local is_age = false
    for _, magic in ipairs(AGE_MAGIC) do
      if head:sub(1, #magic) == magic then is_age = true end
    end
    if not is_age then
      remove(id)
      return say(400, { error = "not an age file" })
    end
    local name = final_name(id, ext)
    assert(os.rename(part, cfg.base .. "/" .. name))
    os.remove(part .. ".len")
    notify(name, size)
    return say(200, { id = id, size = size })
  end)
end

if method == "HEAD" or method == "GET" then
  local size = size_of(part)
  if not size then return say(404) end
  return say(200, nil, { ["Upload-Offset"] = size })
end

if method == "DELETE" then
  return with_lock(id, function()
    remove(id)
    return say(204)
  end)
end

if method == "PATCH" then
  local offset = tonumber(ngx.var.http_upload_offset)
  if not offset or offset < 0 or offset % 1 ~= 0 then return say(400, { error = "Upload-Offset required" }) end
  ngx.req.read_body()
  local body = ngx.req.get_body_file() -- nil only for an empty body
  local n = body and size_of(body) or 0
  return with_lock(id, function()
    local size, declared = size_of(part), meta(id)
    if not size or not declared then return say(404) end -- deleted meanwhile: do not resurrect it
    if size ~= offset then return say(409, nil, { ["Upload-Offset"] = size }) end
    if size + n > declared or size + n > cfg.max_bytes then return say(413) end
    if n > 0 then
      local src, dst = assert(io.open(body, "rb")), assert(io.open(part, "ab"))
      while true do
        local chunk = src:read(1048576)
        if not chunk then break end
        dst:write(chunk)
      end
      src:close()
      dst:close()
    end
    return say(204, nil, { ["Upload-Offset"] = size + n })
  end)
end

return say(405)
