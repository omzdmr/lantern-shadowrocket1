-- Lantern Free TLS + SMUX v1 backend for Shadowrocket
--
-- Outer transport is handled by the Shadowrocket Lua node:
--   TCP -> TLS (peer/SNI from node settings)
--
-- This backend implements:
--   SMUX v1 -> stream 1 -> HTTP CONNECT -> tunneled TCP bytes
--
-- Password field = per-proxy X-Lantern-Auth-Token.

local backend = require 'backend'

local SUCCESS   = backend.RESULT.SUCCESS
local ERROR     = backend.RESULT.ERROR
local HANDSHAKE = backend.RESULT.HANDSHAKE

local get_uuid = backend.get_uuid
local get_host = backend.get_address_host
local get_port = backend.get_address_port
local write_upstream = backend.write
local free = backend.free

local VERSION = 1
local CMD_SYN = 0
local CMD_FIN = 1
local CMD_PSH = 2
local CMD_NOP = 3
local STREAM_ID = 1
local MAX_FRAME = 32768

local token = tostring(settings.password or ""):gsub("[\r\n]", "")
local states = {}

local function le16(n)
    return string.char(n % 256, math.floor(n / 256) % 256)
end

local function le32(n)
    local b1 = n % 256
    n = math.floor(n / 256)
    local b2 = n % 256
    n = math.floor(n / 256)
    local b3 = n % 256
    n = math.floor(n / 256)
    local b4 = n % 256
    return string.char(b1, b2, b3, b4)
end

local function u16le(s, i)
    local a, b = string.byte(s, i, i + 1)
    return a + b * 256
end

local function u32le(s, i)
    local a, b, c, d = string.byte(s, i, i + 3)
    return a + b * 256 + c * 65536 + d * 16777216
end

local function frame(cmd, sid, payload)
    payload = payload or ""
    return string.char(VERSION, cmd) ..
           le16(#payload) ..
           le32(sid) ..
           payload
end

local function frame_data(payload)
    if not payload or #payload == 0 then
        return ""
    end

    local out = {}
    local pos = 1
    while pos <= #payload do
        local last = math.min(pos + MAX_FRAME - 1, #payload)
        local chunk = string.sub(payload, pos, last)
        out[#out + 1] = frame(CMD_PSH, STREAM_ID, chunk)
        pos = last + 1
    end
    return table.concat(out)
end

local function target_for(ctx)
    local host = get_host(ctx)
    local port = get_port(ctx)

    if string.find(host, ":", 1, true) and string.sub(host, 1, 1) ~= "[" then
        host = "[" .. host .. "]"
    end

    return host .. ":" .. tostring(port)
end

local function connect_request(ctx)
    local target = target_for(ctx)

    -- Headers used by Lantern's chained HTTPS CONNECT path.
    return
        "CONNECT " .. target .. " HTTP/1.1\r\n" ..
        "Host: " .. target .. "\r\n" ..
        "Proxy-Connection: Keep-Alive\r\n" ..
        "User-Agent: Go-http-client/1.1\r\n" ..
        "X-Lantern-Auth-Token: " .. token .. "\r\n" ..
        "X-Lantern-Device-Id: a34113\r\n" ..
        "X-Lantern-Version: 7.6.179\r\n" ..
        "X-Lantern-App-Version: 9999.99.99\r\n" ..
        "X-Lantern-Platform: android\r\n" ..
        "X-Lantern-Pro-Token: K1qttSsZruN\r\n" ..
        "X-Lantern-User-Id: 381696446\r\n" ..
        "X-Lantern-Time-Zone: Asia/Shanghai\r\n" ..
        "X-BBR: y\r\n" ..
        "\r\n"
end

local function get_state(ctx)
    local id = get_uuid(ctx)
    local st = states[id]
    if not st then
        st = {
            started = false,
            established = false,
            raw = "",
            connect_buf = "",
            pending = ""
        }
        states[id] = st
    end
    return st
end

-- We transform both directions ourselves, so don't request DIRECT_WRITE.
function wa_lua_on_flags_cb(ctx)
    get_state(ctx)
    return 0
end

function wa_lua_on_handshake_cb(ctx)
    local st = get_state(ctx)

    if st.established then
        return true
    end

    if not st.started then
        if token == "" then
            return false
        end

        -- Open client stream #1, then send the HTTP CONNECT inside that stream.
        local initial =
            frame(CMD_SYN, STREAM_ID, "") ..
            frame_data(connect_request(ctx))

        write_upstream(ctx, initial)
        st.started = true
    end

    return false
end

local function parse_smux(st, incoming)
    st.raw = st.raw .. (incoming or "")
    local payloads = {}
    local saw_fin = false

    while #st.raw >= 8 do
        local ver = string.byte(st.raw, 1)
        local cmd = string.byte(st.raw, 2)
        local len = u16le(st.raw, 3)
        local sid = u32le(st.raw, 5)
        local total = 8 + len

        if #st.raw < total then
            break
        end

        local payload = ""
        if len > 0 then
            payload = string.sub(st.raw, 9, total)
        end
        st.raw = string.sub(st.raw, total + 1)

        if ver ~= VERSION then
            return nil, "unsupported smux version " .. tostring(ver)
        end

        -- NOP is session keepalive. Ignore it.
        if cmd == CMD_NOP then
            -- no-op

        elseif sid == STREAM_ID then
            if cmd == CMD_PSH then
                if #payload > 0 then
                    payloads[#payloads + 1] = payload
                end
            elseif cmd == CMD_FIN then
                saw_fin = true
            elseif cmd == CMD_SYN then
                -- Server-initiated SYN for the same stream is not expected.
                -- Ignore rather than leaking framing to the browser.
            end
        else
            -- This minimal client owns only stream #1.
            -- Ignore unrelated server streams.
        end
    end

    return table.concat(payloads), nil, saw_fin
end

function wa_lua_on_read_cb(ctx, buf)
    local st = get_state(ctx)

    local stream_bytes, err, saw_fin = parse_smux(st, buf)
    if err then
        return ERROR, nil
    end

    if not st.established then
        if stream_bytes and #stream_bytes > 0 then
            st.connect_buf = st.connect_buf .. stream_bytes
        end

        local p = string.find(st.connect_buf, "\r\n\r\n", 1, true)
        if not p then
            if saw_fin then
                return ERROR, nil
            end
            return SUCCESS, nil
        end

        local header = string.sub(st.connect_buf, 1, p + 3)
        local code = tonumber(string.match(header, "^HTTP/%d+%.%d+%s+(%d+)") or "0")

        if code < 200 or code >= 300 then
            return ERROR, nil
        end

        st.established = true

        -- Preserve any tunneled bytes that arrived in the same SMUX frame
        -- immediately after the CONNECT response header.
        local tail = string.sub(st.connect_buf, p + 4)
        st.connect_buf = ""

        if #tail > 0 then
            return HANDSHAKE, tail
        end
        return HANDSHAKE, nil
    end

    if saw_fin and (not stream_bytes or #stream_bytes == 0) then
        return ERROR, nil
    end

    if stream_bytes and #stream_bytes > 0 then
        -- We have removed SMUX framing, so return transformed bytes.
        return SUCCESS, stream_bytes
    end

    return SUCCESS, nil
end

function wa_lua_on_write_cb(ctx, buf)
    local st = get_state(ctx)

    if not st.established then
        -- Shadowrocket normally won't call this before HANDSHAKE,
        -- but don't leak unframed bytes if it does.
        return SUCCESS, nil
    end

    return SUCCESS, frame_data(buf)
end

function wa_lua_on_close_cb(ctx)
    local id = get_uuid(ctx)
    local st = states[id]

    if st and st.started then
        -- Best-effort stream FIN. Ignore failures during teardown.
        pcall(function()
            write_upstream(ctx, frame(CMD_FIN, STREAM_ID, ""))
        end)
    end

    states[id] = nil
    free(ctx)
    return SUCCESS
end
