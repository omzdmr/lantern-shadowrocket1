-- Lantern HTTPS proxy backend for Shadowrocket
-- Mirrors Shadowrocket's official http-backend.lua handshake flow,
-- with Lantern authentication headers added.

local backend = require 'backend'

local DIRECT_WRITE = backend.SUPPORT.DIRECT_WRITE
local SUCCESS = backend.RESULT.SUCCESS
local HANDSHAKE = backend.RESULT.HANDSHAKE
local DIRECT = backend.RESULT.DIRECT

local ctx_uuid = backend.get_uuid
local ctx_address_host = backend.get_address_host
local ctx_address_port = backend.get_address_port
local ctx_write = backend.write
local ctx_free = backend.free

local flags = {}
local SENT = 1
local RECEIVED = 2

local token = tostring(settings.password or ""):gsub("[\r\n]", "")

function wa_lua_on_flags_cb(ctx)
    return DIRECT_WRITE
end

function wa_lua_on_handshake_cb(ctx)
    local uuid = ctx_uuid(ctx)

    if flags[uuid] == RECEIVED then
        return true
    end

    if flags[uuid] ~= SENT then
        local host = ctx_address_host(ctx)
        local port = ctx_address_port(ctx)
        local target = host .. ":" .. tostring(port)

        local req =
            "CONNECT " .. target .. " HTTP/1.1\r\n" ..
            "Host: " .. target .. "\r\n" ..
            "Proxy-Connection: Keep-Alive\r\n" ..
            "X-Lantern-Auth-Token: " .. token .. "\r\n" ..
            "X-Lantern-Device-Id: a34113\r\n" ..
            "\r\n"

        ctx_write(ctx, req)
        flags[uuid] = SENT
    end

    return false
end

function wa_lua_on_read_cb(ctx, buf)
    local uuid = ctx_uuid(ctx)

    -- This intentionally mirrors Shadowrocket's official HTTP backend:
    -- the first upstream read after CONNECT completes the handshake.
    if flags[uuid] == SENT then
        flags[uuid] = RECEIVED
        return HANDSHAKE, nil
    end

    return DIRECT, buf
end

function wa_lua_on_write_cb(ctx, buf)
    return DIRECT, buf
end

function wa_lua_on_close_cb(ctx)
    local uuid = ctx_uuid(ctx)
    flags[uuid] = nil
    ctx_free(ctx)
    return SUCCESS
end
