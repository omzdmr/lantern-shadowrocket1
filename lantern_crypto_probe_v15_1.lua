-- Lantern / Shadowrocket crypto capability probe v15.1
-- Diagnostic only. Uses dummy keys/IVs/plaintext and never embeds or prints Lantern credentials,
-- tickets, certificates, session state, master secrets or auth tokens.
-- Goal: map the exact Shadowrocket Lua crypto API needed before attempting TLS 1.2 records.

local backend = require 'backend'
local crypto = require 'crypto'

local SUCCESS = backend.RESULT.SUCCESS
local ERROR = backend.RESULT.ERROR
local ctx_write = backend.write
local ctx_free = backend.free
local debug = backend.debug

local report = {}
local sent = false

local function add(k, v)
    report[#report + 1] = tostring(k) .. '=' .. tostring(v)
end

local function safe(fn)
    local ok, a, b, c = pcall(fn)
    if ok then return true, a, b, c end
    return false, tostring(a)
end

local function typename(v)
    local ok, t = pcall(type, v)
    return ok and t or 'unknown'
end

local function field_type(obj, key)
    if obj == nil then return 'missing' end
    local ok, value = pcall(function() return obj[key] end)
    if not ok then return 'error' end
    return type(value)
end

local function call_final(obj)
    if field_type(obj, 'final') ~= 'function' then return '' end
    local out = obj:final()
    if out == nil then return '' end
    return out
end

local function method_map(obj, prefix, names)
    if obj == nil then return end
    for _, name in ipairs(names) do
        add(prefix .. '.' .. name, field_type(obj, name))
    end
end

add('probe', 'lantern-crypto-v15.1')
add('crypto', typename(crypto))

for _, name in ipairs({
    'rand', 'encrypt', 'decrypt', 'digest', 'hash', 'hmac', 'mac',
    'aead', 'cipher', 'kdf', 'hkdf', 'pbkdf2'
}) do
    add('crypto.' .. name, field_type(crypto, name))
end

-- Random API. Shadowrocket's public Lua example uses crypto.rand.bytes(n).
if crypto.rand then
    method_map(crypto.rand, 'rand', {'bytes'})
    if field_type(crypto.rand, 'bytes') == 'function' then
        for _, n in ipairs({1, 16, 32}) do
            local ok, value = safe(function() return crypto.rand.bytes(n) end)
            if ok and type(value) == 'string' then
                add('rand.bytes.' .. n, 'ok,len:' .. #value)
            else
                add('rand.bytes.' .. n, ok and ('type:' .. type(value)) or ('error:' .. value))
            end
        end
    end
end

-- Digest/hash API shape probes. No real material is used.
local function probe_digest_container(label, obj)
    if obj == nil then return end
    method_map(obj, label, {'new', 'digest', 'hash', 'sha256', 'sha384'})

    if field_type(obj, 'new') == 'function' then
        for _, alg in ipairs({'sha256', 'SHA256', 'sha384', 'SHA384'}) do
            local ok, value = safe(function()
                local d = obj.new(alg)
                local update_type = field_type(d, 'update')
                local final_type = field_type(d, 'final')
                if update_type ~= 'function' or final_type ~= 'function' then
                    return 'object:update=' .. update_type .. ',final=' .. final_type
                end
                d:update('abc')
                local out = d:final()
                return 'ok,len:' .. (type(out) == 'string' and #out or -1)
            end)
            add(label .. '.new.' .. alg, ok and value or ('error:' .. value))
        end
    end
end

probe_digest_container('digest', crypto.digest)
probe_digest_container('hash', crypto.hash)

-- HMAC/MAC API shape probes. Dummy key/data only.
local function probe_mac_container(label, obj)
    if obj == nil then return end
    method_map(obj, label, {'new', 'digest', 'hmac', 'sha256', 'sha384'})

    if field_type(obj, 'new') == 'function' then
        for _, alg in ipairs({'sha256', 'SHA256', 'sha384', 'SHA384'}) do
            local ok, value = safe(function()
                local m = obj.new(alg, string.rep('\0', 16))
                local update_type = field_type(m, 'update')
                local final_type = field_type(m, 'final')
                if update_type ~= 'function' or final_type ~= 'function' then
                    return 'object:update=' .. update_type .. ',final=' .. final_type
                end
                m:update('abc')
                local out = m:final()
                return 'ok,len:' .. (type(out) == 'string' and #out or -1)
            end)
            add(label .. '.new.' .. alg, ok and value or ('error:' .. value))
        end
    end
end

probe_mac_container('hmac', crypto.hmac)
probe_mac_container('mac', crypto.mac)

-- Cipher constructor + round-trip probes.
-- CFB/OFB entries are known from Shadowrocket's public lightsword backend.
-- GCM/CTR/CBC are tested because TLS 1.2 implementation feasibility depends on them.
local cipher_tests = {
    {'aes-128-gcm', 16, 12},
    {'aes-128-gcm', 16, 16},
    {'aes-256-gcm', 32, 12},
    {'aes-256-gcm', 32, 16},
    {'aes-128-ctr', 16, 16},
    {'aes-256-ctr', 32, 16},
    {'aes-128-cbc', 16, 16},
    {'aes-256-cbc', 32, 16},
    {'aes-128-cfb', 16, 16},
    {'aes-256-cfb', 32, 16},
    {'aes-128-ofb', 16, 16},
    {'aes-256-ofb', 32, 16},
}

add('encrypt.new', field_type(crypto.encrypt, 'new'))
add('decrypt.new', field_type(crypto.decrypt, 'new'))

if crypto.encrypt and crypto.decrypt
    and field_type(crypto.encrypt, 'new') == 'function'
    and field_type(crypto.decrypt, 'new') == 'function' then

    for _, t in ipairs(cipher_tests) do
        local name, klen, ivlen = t[1], t[2], t[3]
        local key = string.rep('\0', klen)
        local iv = string.rep('\0', ivlen)
        local plain = '0123456789abcdef0123456789abcdef'

        local ok, value = safe(function()
            local enc = crypto.encrypt.new(name, key, iv)
            local api = {}
            for _, m in ipairs({'update', 'final', 'aad', 'set_aad', 'tag', 'get_tag', 'set_tag'}) do
                api[#api + 1] = m .. ':' .. field_type(enc, m)
            end

            if field_type(enc, 'update') ~= 'function' then
                return 'ctor-ok,' .. table.concat(api, ',')
            end

            local cipher = enc:update(plain) .. call_final(enc)

            local dec = crypto.decrypt.new(name, key, iv)
            if field_type(dec, 'update') ~= 'function' then
                return 'enc-ok,len:' .. #cipher .. ',decrypt.update:' .. field_type(dec, 'update') .. ',' .. table.concat(api, ',')
            end

            local recovered = dec:update(cipher) .. call_final(dec)
            local roundtrip = recovered == plain and 'yes' or ('no,len:' .. #recovered)
            return 'ok,cipherlen:' .. #cipher .. ',roundtrip:' .. roundtrip .. ',' .. table.concat(api, ',')
        end)

        add('cipher.' .. name .. '.iv' .. ivlen, ok and value or ('error:' .. value))
    end
end

-- Direct-call probes for runtimes exposing hash/HMAC as functions rather than containers.
if type(crypto.digest) == 'function' then
    for _, alg in ipairs({'sha256', 'SHA256'}) do
        local ok, value = safe(function() return crypto.digest(alg, 'abc') end)
        add('digest.call.' .. alg, ok and ('ok,type:' .. type(value) .. ',len:' .. (type(value) == 'string' and #value or -1)) or ('error:' .. value))
    end
end

if type(crypto.hash) == 'function' then
    for _, alg in ipairs({'sha256', 'SHA256'}) do
        local ok, value = safe(function() return crypto.hash(alg, 'abc') end)
        add('hash.call.' .. alg, ok and ('ok,type:' .. type(value) .. ',len:' .. (type(value) == 'string' and #value or -1)) or ('error:' .. value))
    end
end

if type(crypto.hmac) == 'function' then
    for _, alg in ipairs({'sha256', 'SHA256'}) do
        local ok, value = safe(function() return crypto.hmac(alg, 'abc', string.rep('\0', 16)) end)
        add('hmac.call.' .. alg, ok and ('ok,type:' .. type(value) .. ',len:' .. (type(value) == 'string' and #value or -1)) or ('error:' .. value))
    end
end

local output = table.concat(report, '\n') .. '\n'

function wa_lua_on_flags_cb(ctx)
    return 0
end

function wa_lua_on_handshake_cb(ctx)
    if not sent then
        debug(output)
        -- Keep the diagnostic visible in backend traffic/logs as well as debug output.
        -- The payload contains capability names and dummy-test results only.
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
