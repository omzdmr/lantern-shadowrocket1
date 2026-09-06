-- Lantern TLS diagnostic backend for Shadowrocket
-- Minimal CONNECT handshake + verbose debug

local backend = require 'backend'

local SUCCESS = backend.RESULT.SUCCESS
local ERROR = backend.RESULT.ERROR
local HANDSHAKE = backend.RESULT.HANDSHAKE
local DIRECT = backend.RESULT.DIRECT
local DIRECT_WRITE = backend.SUPPORT.DIRECT_WRITE

local get_uuid = backend.get_uuid
local get_host = backend.get_address_host
local get_port = backend.get_address_port
local write = backend.write
local free = backend.free
local debug = backend.debug

local state = {}
local token = tostring(settings.password or ""):gsub("[\r\n]", "")

local function target(ctx)
    local h = get_host(ctx)
    local p = get_port(ctx)
    if h:find(":", 1, true) and h:sub(1,1) ~= "[" then
        h = "[" .. h .. "]"
    end
    return h .. ":" .. tostring(p)
end

function wa_lua_on_flags_cb(ctx)
    local id = get_uuid(ctx)
    state[id] = {sent=false, established=false, buf=""}
    debug("LanternDiag: FLAGS")
    return DIRECT_WRITE
end

function wa_lua_on_handshake_cb(ctx)
    local id = get_uuid(ctx)
    local s = state[id]
    if not s then
        s = {sent=false, established=false, buf=""}
        state[id] = s
    end

    debug("LanternDiag: HANDSHAKE")

    if s.established then
        return true
    end

    if not s.sent then
        if token == "" then
            debug("LanternDiag: EMPTY TOKEN")
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

        debug("LanternDiag: SEND CONNECT " .. t)
        write(ctx, req)
        s.sent = true
    end

    return false
end

function wa_lua_on_read_cb(ctx, buf)
    local id = get_uuid(ctx)
    local s = state[id]
    if not s then
        debug("LanternDiag: READ WITHOUT STATE")
        return ERROR, nil
    end

    debug("LanternDiag: READ bytes=" .. tostring(#buf))

    if not s.established then
        s.buf = s.buf .. buf
        local e = s.buf:find("\r\n\r\n", 1, true)

        if not e then
            local preview = s.buf:gsub("\r","\\r"):gsub("\n","\\n")
            if #preview > 180 then preview = preview:sub(1,180) end
            debug("LanternDiag: PARTIAL " .. preview)
            return SUCCESS, nil
        end

        local header = s.buf:sub(1, e+3)
        local first = header:match("([^\r\n]+)") or "<no status line>"
        debug("LanternDiag: RESPONSE " .. first)

        local code = tonumber(header:match("^HTTP/%d+%.%d+%s+(%d+)") or "0")
        if code < 200 or code >= 300 then
            return ERROR, nil
        end

        s.established = true
        local tail = s.buf:sub(e+4)
        s.buf = ""

        debug("LanternDiag: CONNECT OK")
        if #tail > 0 then
            return HANDSHAKE, tail
        end
        return HANDSHAKE, nil
    end

    return DIRECT, buf
end

function wa_lua_on_write_cb(ctx, buf)
    debug("LanternDiag: WRITE bytes=" .. tostring(#buf))
    return DIRECT, buf
end

function wa_lua_on_close_cb(ctx)
    local id = get_uuid(ctx)
    state[id] = nil
    debug("LanternDiag: CLOSE")
    free(ctx)
    return SUCCESS
end
