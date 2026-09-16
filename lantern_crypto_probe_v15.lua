-- Lantern / Shadowrocket crypto capability probe v15
-- No Lantern credentials, tickets, master secrets, certificates or session state are embedded here.
-- Purpose: determine what the Shadowrocket Lua runtime exposes before implementing TLS 1.2 records.

local backend = require 'backend'
local crypto = require 'crypto'

local SUCCESS = backend.RESULT.SUCCESS
local ERROR = backend.RESULT.ERROR
local ctx_write = backend.write
local ctx_free = backend.free
local debug = backend.debug

local function yesno(v)
    return v and 'yes' or 'no'
end

local function safe(fn)
    local ok, value = pcall(fn)
    if ok then return true, value end
    return false, tostring(value)
end

local report = {}
local function add(k, v)
    report[#report + 1] = k .. '=' .. tostring(v)
end

add('probe', 'lantern-crypto-v15')
add('crypto.digest', yesno(crypto.digest))
add('crypto.encrypt', yesno(crypto.encrypt))
add('crypto.decrypt', yesno(crypto.decrypt))
add('crypto.rand', yesno(crypto.rand))

if crypto.rand then
    local ok, value = safe(function() return crypto.rand.bytes(16) end)
    add('rand.bytes.16', ok and (#value == 16 and 'yes' or ('len:' .. #value)) or ('error:' .. value))
end

if crypto.digest and crypto.digest.new then
    for _, alg in ipairs({'SHA256', 'sha256', 'SHA384', 'sha384'}) do
        local ok, value = safe(function()
            local d = crypto.digest.new(alg)
            d:update('abc')
            return d:final()
        end)
        add('digest.' .. alg, ok and ('yes,len:' .. #value) or ('error:' .. value))
    end
end

-- Probe cipher names without any real Lantern material.
-- Test vectors use zero-filled dummy key/IV only.
if crypto.encrypt and crypto.encrypt.new then
    local tests = {
        {'aes-128-gcm', 16, 12},
        {'aes-128-gcm', 16, 16},
        {'aes-128-ctr', 16, 16},
        {'aes-128-cbc', 16, 16},
        {'aes-128-cfb', 16, 16},
    }
    for _, t in ipairs(tests) do
        local name, klen, ivlen = t[1], t[2], t[3]
        local ok, value = safe(function()
            local c = crypto.encrypt.new(name, string.rep('\0', klen), string.rep('\0', ivlen))
            local out = c:update(string.rep('\0', 16)) .. c:final()
            return out
        end)
        add('encrypt.' .. name .. '.iv' .. ivlen, ok and ('yes,len:' .. #value) or ('error:' .. value))
    end
end

-- Presence-only probes. We deliberately do not dump table contents or secret-bearing state.
for _, k in ipairs({'hmac', 'mac', 'aead', 'cipher', 'kdf', 'hkdf', 'pbkdf2'}) do
    add('crypto.' .. k, yesno(crypto[k]))
end

local output = table.concat(report, '\n') .. '\n'
local sent = false

function wa_lua_on_flags_cb(ctx)
    return 0
end

function wa_lua_on_handshake_cb(ctx)
    if not sent then
        debug(output)
        -- Sending this to the selected test endpoint makes the probe visible in backend logs/traffic.
        -- It contains capability names only, never Lantern secrets.
        ctx_write(ctx, output)
        sent = true
    end
    return false
end

function wa_lua_on_read_cb(ctx, buf)
    return ERROR, nil
end

function wa_lua_on_write_cb(ctx, buf)
    return ERROR, nil
end

function wa_lua_on_close_cb(ctx)
    ctx_free(ctx)
    return SUCCESS
end
