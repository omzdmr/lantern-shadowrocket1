-- Lantern TLS visible diagnostic backend for Shadowrocket
-- Converts the Lantern CONNECT response into a visible HTTP page in Safari.

local backend = require 'backend'

local SUCCESS = backend.RESULT.SUCCESS
local ERROR = backend.RESULT.ERROR
local HANDSHAKE = backend.RESULT.HANDSHAKE
local DIRECT_WRITE = backend.SUPPORT.DIRECT_WRITE

local get_uuid = backend.get_uuid
local get_host = backend.get_address_host
local get_port = backend.get_address_port
local write = backend.write
local free = backend.free

local states = {}
local token = tostring(settings.password or ""):gsub("[\r\n]", "")

local function target(ctx)
    local h = get_host(ctx)
    local p = get_port(ctx)
    if h:find(":", 1, true) and h:sub(1,1) ~= "[" then
        h = "[" .. h .. "]"
    end
    return h .. ":" .. tostring(p)
end

local function esc(s)
    s = tostring(s or "")
    s = s:gsub("&","&amp;"):gsub("<","&lt;"):gsub(">","&gt;")
    return s
end

local function page(title, body)
    local html =
        "<!doctype html><meta charset=utf-8>" ..
        "<meta name=viewport content='width=device-width,initial-scale=1'>" ..
        "<title>" .. esc(title) .. "</title>" ..
        "<style>body{font-family:-apple-system,system-ui;margin:24px;line-height:1.45}" ..
        "pre{white-space:pre-wrap;word-break:break-word;background:#111;color:#eee;padding:16px;border-radius:12px}</style>" ..
        "<h1>" .. esc(title) .. "</h1><pre>" .. esc(body) .. "</pre>"
    return "HTTP/1.1 200 OK\r\n" ..
           "Content-Type: text/html; charset=utf-8\r\n" ..
           "Content-Length: " .. tostring(#html) .. "\r\n" ..
           "Connection: close\r\n\r\n" ..
           html
end

function wa_lua_on_flags_cb(ctx)
    local id = get_uuid(ctx)
    states[id] = {sent=false, buf="", shown=false}
    return DIRECT_WRITE
end

function wa_lua_on_handshake_cb(ctx)
    local id = get_uuid(ctx)
    local s = states[id]
    if not s then
        s = {sent=false, buf="", shown=false}
        states[id] = s
    end

    if s.shown then
        return true
    end

    if not s.sent then
        if token == "" then
            s.shown = true
            write(ctx, "")
            return false
        end

        local t = target(ctx)
        local req =
            "CONNECT " .. t .. " HTTP/1.1\r\n" ..
            "Host: " .. t .. "\r\n" ..
            "Proxy-Connection: Keep-Alive\r\n" ..
            "X-Lantern-Auth-Token: " .. token .. "\r\n" ..
            "X-Lantern-Device-Id: a34113\r\n" ..
            "\r\n"

        write(ctx, req)
        s.sent = true
    end

    return false
end

function wa_lua_on_read_cb(ctx, buf)
    local id = get_uuid(ctx)
    local s = states[id]
    if not s then
        return ERROR, nil
    end

    if s.shown then
        return SUCCESS, nil
    end

    s.buf = s.buf .. buf

    -- We only need enough bytes to expose what the Lantern server answered.
    local endpos = s.buf:find("\r\n\r\n", 1, true)
    if not endpos and #s.buf < 4096 then
        return SUCCESS, nil
    end

    local raw = s.buf
    if #raw > 3000 then raw = raw:sub(1,3000) end

    local first = raw:match("([^\r\n]+)") or "<no HTTP status line>"
    local code = tonumber(raw:match("^HTTP/%d+%.%d+%s+(%d+)") or "0")

    local title
    if code >= 200 and code < 300 then
        title = "LANTERN CONNECT OK"
    elseif code > 0 then
        title = "LANTERN CONNECT REDDEDILDI"
    else
        title = "LANTERN BEKLENMEYEN CEVAP"
    end

    local visible =
        "Upstream response:\n" .. first ..
        "\n\nRaw preview:\n" .. raw

    s.shown = true
    -- Mark Lua handshake complete and inject an HTTP page to the client.
    return HANDSHAKE, page(title, visible)
end

function wa_lua_on_write_cb(ctx, buf)
    local id = get_uuid(ctx)
    local s = states[id]

    -- This is a diagnostic backend. Once the result page is injected,
    -- swallow the browser's pending request instead of forwarding it.
    if s and s.shown then
        return SUCCESS, nil
    end

    return SUCCESS, nil
end

function wa_lua_on_close_cb(ctx)
    local id = get_uuid(ctx)
    states[id] = nil
    free(ctx)
    return SUCCESS
end
