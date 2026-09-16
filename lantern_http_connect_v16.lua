-- Lantern TLS proxy -> HTTP CONNECT backend for Shadowrocket
-- Uses Shadowrocket's own TLS layer. The Lua backend only adds Lantern's
-- X-Lantern-Auth-Token header and establishes the requested CONNECT tunnel.
-- Put the live Lantern auth token in the node Password field. Never commit it.

local backend = require 'backend'

local DIRECT_WRITE = backend.SUPPORT.DIRECT_WRITE
local SUCCESS = backend.RESULT.SUCCESS
local HANDSHAKE = backend.RESULT.HANDSHAKE
local DIRECT = backend.RESULT.DIRECT
local ERROR = backend.RESULT.ERROR

local ctx_uuid = backend.get_uuid
local ctx_address_host = backend.get_address_host
local ctx_address_port = backend.get_address_port
local ctx_write = backend.write
local ctx_free = backend.free
local debug = backend.debug

local state = {}

local function token()
    if type(settings) == 'table' and type(settings.password) == 'string' then
        return settings.password
    end
    return ''
end

local function safe_target(ctx)
    local host = ctx_address_host(ctx) or ''
    local port = tonumber(ctx_address_port(ctx)) or 0
    return host, port
end

function wa_lua_on_flags_cb(ctx)
    return DIRECT_WRITE
end

function wa_lua_on_handshake_cb(ctx)
    local id = ctx_uuid(ctx)
    local s = state[id]
    if not s then
        s = { sent = false, established = false, buffer = '' }
        state[id] = s
    end

    if s.established then
        return true
    end

    if not s.sent then
        local auth = token()
        if auth == '' then
            debug('lantern-v16 connect: missing Password/auth token')
            return false
        end

        local host, port = safe_target(ctx)
        if host == '' or port <= 0 then
            debug('lantern-v16 connect: missing target host/port')
            return false
        end

        local authority = host .. ':' .. tostring(port)
        local req = 'CONNECT ' .. authority .. ' HTTP/1.1\r\n' ..
                    'Host: ' .. authority .. '\r\n' ..
                    'X-Lantern-Auth-Token: ' .. auth .. '\r\n' ..
                    'Proxy-Connection: Keep-Alive\r\n' ..
                    '\r\n'
        ctx_write(ctx, req)
        s.sent = true
        debug('lantern-v16 connect: request sent target=' .. authority .. ' tokenLen=' .. tostring(#auth))
    end

    return false
end

function wa_lua_on_read_cb(ctx, buf)
    local id = ctx_uuid(ctx)
    local s = state[id]
    if not s then
        s = { sent = false, established = false, buffer = '' }
        state[id] = s
    end

    if s.established then
        return DIRECT, buf
    end

    s.buffer = s.buffer .. (buf or '')
    local header_end = string.find(s.buffer, '\r\n\r\n', 1, true)
    if not header_end then
        if #s.buffer > 32768 then
            debug('lantern-v16 connect: oversized proxy response')
            return ERROR, nil
        end
        return SUCCESS, nil
    end

    local head = string.sub(s.buffer, 1, header_end + 3)
    local status = string.match(head, '^HTTP/%d+%.%d+%s+(%d%d%d)')
    if status ~= '200' then
        debug('lantern-v16 connect: proxy rejected CONNECT status=' .. tostring(status or 'unknown'))
        return ERROR, nil
    end

    s.established = true
    s.buffer = ''
    debug('lantern-v16 connect: CONNECT 200 established')
    return HANDSHAKE, nil
end

function wa_lua_on_write_cb(ctx, buf)
    return DIRECT, buf
end

function wa_lua_on_close_cb(ctx)
    local id = ctx_uuid(ctx)
    state[id] = nil
    ctx_free(ctx)
    return SUCCESS
end
