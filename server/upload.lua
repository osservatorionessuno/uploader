-- Uploader backend (content_by_lua_file), deployed by deploy/roles/uploader.
--   POST   /up            create, Upload-Length required            -> 201 {"id"}
--   HEAD   /up/<id>       bytes held                                -> 200 Upload-Offset
--   PATCH  /up/<id>       append at Upload-Offset                   -> 204 Upload-Offset | 409 Upload-Offset
--   POST   /up/<id>/done  size == declared, age magic, store, notify -> 200 {"id","size"} | 409 | 400
--   DELETE /up/<id>       drop the partial                          -> 204
--   POST   /up/form       no-JavaScript multipart path              -> result.html
-- State is the filesystem: <base>/tmp/<id> (partial; its size is the offset), <id>.len
-- (declared total), <base>/<id>.age (finished). nginx spools bodies to disk first, Lua only
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

-- Telegram via the internal /_tg proxy (the token lives there). Best effort: failures are only logged.
local function notify(id, size)
  if not cfg.telegram_chat_id then return end
  local text = string.format("%s: nuovo file %s (%.1f MiB)", cfg.domain, id, size / 1048576)
  local res = ngx.location.capture("/_tg", {
    method = ngx.HTTP_POST,
    body = cjson.encode({ chat_id = cfg.telegram_chat_id, text = text }),
  })
  if res.status ~= 200 then ngx.log(ngx.ERR, "upload: telegram ", res.status, " ", res.body) end
end

-- Answer to the no-JavaScript form: result.html from the web root with __CLASS__ and __ID__ filled.
local function page(status, class, id)
  ngx.status = status
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["Content-Type"] = "text/html; charset=utf-8"
  local html = read_all(ngx.var.document_root .. "/result.html") or "<h1>__CLASS__ __ID__</h1>"
  ngx.print((html:gsub("__CLASS__", class):gsub("__ID__", id or "")))
end

-- Store [from, to) of the spooled body as a finished upload: magic check, size cap, notify.
local function store_range(body, from, to)
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
  assert(os.rename(TMP .. id, cfg.base .. "/" .. id .. ".age"))
  notify(id, size)
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
  return store_range(body, hend, total - tail_len + tpos - 1)
end

if ngx.var.uri == "/up" then
  if method ~= "POST" then return say(405) end
  local length = tonumber(ngx.var.http_upload_length)
  if not length or length <= 0 or length % 1 ~= 0 then return say(400, { error = "Upload-Length required" }) end
  if length > cfg.max_bytes then return say(413) end
  local id = rand_id()
  write(TMP .. id, "")
  write(TMP .. id .. ".len", tostring(length))
  return say(201, { id = id })
end

local m = ngx.re.match(ngx.var.uri, [[^/up/([a-f0-9]{32})(/done)?$]], "jo")
if not m then return say(404) end
local id, finalize = m[1], m[2]
local part = TMP .. id

if finalize then
  if method ~= "POST" then return say(405) end
  return with_lock(id, function()
    local size, declared = size_of(part), tonumber(read_all(part .. ".len") or "")
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
    assert(os.rename(part, cfg.base .. "/" .. id .. ".age"))
    os.remove(part .. ".len")
    notify(id, size)
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
    local size, declared = size_of(part), tonumber(read_all(part .. ".len") or "")
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
