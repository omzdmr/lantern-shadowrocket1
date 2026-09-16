-- Lantern / Shadowrocket crypto capability probe v15.2
-- Targeted TLS 1.2 feasibility probe. Uses public test vectors and zero/dummy material only.
-- Never embeds or prints Lantern credentials, tickets, certificates, session state or master secrets.

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
    local ok, a, b, c, d, e = pcall(fn)
    if ok then return true, a, b, c, d, e end
    return false, tostring(a)
end

local function ftype(obj, key)
    if obj == nil then return 'missing' end
    local ok, value = pcall(function() return obj[key] end)
    if not ok then return 'error' end
    return type(value)
end

local HEX = '0123456789abcdef'
local function hex(s)
    if type(s) ~= 'string' then return '' end
    local out = {}
    for i = 1, #s do
        local b = string.byte(s, i)
        out[#out + 1] = string.sub(HEX, math.floor(b / 16) + 1, math.floor(b / 16) + 1)
        out[#out + 1] = string.sub(HEX, (b % 16) + 1, (b % 16) + 1)
    end
    return table.concat(out)
end

local function flip_first_byte(s)
    if type(s) ~= 'string' or #s == 0 then return s end
    local b = string.byte(s, 1)
    local nb = (b == 0) and 1 or (b - 1)
    return string.char(nb) .. string.sub(s, 2)
end

local function pack_returns(fn)
    local ok, packed = pcall(function()
        local function pack(...)
            return { n = select('#', ...), ... }
        end
        return pack(fn())
    end)
    if not ok then return false, tostring(packed) end
    return true, packed
end

local function describe_returns(prefix, packed, expected_tag_hex)
    add(prefix .. '.n', packed.n or -1)
    for i = 1, math.min(packed.n or 0, 4) do
        local v = packed[i]
        local t = type(v)
        if t == 'string' then
            local h = hex(v)
            local extra = ''
            if expected_tag_hex and h == expected_tag_hex then extra = ',matches-tag:yes' end
            add(prefix .. '.' .. i, 'string,len:' .. #v .. extra)
        else
            add(prefix .. '.' .. i, t .. ':' .. tostring(v))
        end
    end
end

add('probe', 'lantern-crypto-v15.2')
add('crypto.hex', ftype(crypto, 'hex'))
add('crypto.list', ftype(crypto, 'list'))
add('string.pack', type(string.pack))

local ok_bit, bit_mod = pcall(require, 'bit')
add('require.bit', ok_bit and type(bit_mod) or 'no')
local ok_bit32, bit32_mod = pcall(require, 'bit32')
add('require.bit32', ok_bit32 and type(bit32_mod) or 'no')

-- Cipher inventory, filtered to TLS-relevant AES modes.
if type(crypto.list) == 'function' then
    local ok, list = safe(function() return crypto.list('ciphers') end)
    if ok and type(list) == 'table' then
        local have = {}
        for _, name in ipairs(list) do have[tostring(name):lower()] = true end
        for _, name in ipairs({
            'aes-128-ecb', 'aes-256-ecb',
            'aes-128-cbc', 'aes-256-cbc',
            'aes-128-ctr', 'aes-256-ctr',
            'aes-128-gcm', 'aes-256-gcm'
        }) do
            add('list.' .. name, have[name] and 'yes' or 'no')
        end
    else
        add('list.ciphers', ok and ('type:' .. type(list)) or ('error:' .. list))
    end
end

-- SHA raw-output behavior. LuaCrypto normally returns hex unless raw=true.
local SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
if crypto.digest and type(crypto.digest.new) == 'function' then
    local ok, value = safe(function()
        local d = crypto.digest.new('sha256')
        d:update('abc')
        return d:final(nil, true)
    end)
    if ok and type(value) == 'string' then
        add('sha256.final.nil.true', 'len:' .. #value .. ',known:' .. (hex(value) == SHA256_ABC and 'yes' or 'no'))
    else
        add('sha256.final.nil.true', ok and ('type:' .. type(value)) or ('error:' .. value))
    end

    local ok2, value2 = safe(function()
        local d = crypto.digest.new('sha256')
        d:update('abc')
        return d:final(true)
    end)
    if ok2 and type(value2) == 'string' then
        add('sha256.final.true', 'len:' .. #value2 .. ',known:' .. (hex(value2) == SHA256_ABC and 'yes' or 'no'))
    else
        add('sha256.final.true', ok2 and ('type:' .. type(value2)) or ('error:' .. value2))
    end
end

-- HMAC-SHA256 public known-answer test.
local HMAC_DATA = 'The quick brown fox jumps over the lazy dog'
local HMAC_KEY = 'key'
local HMAC_SHA256_EXPECT = 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8'
if crypto.hmac then
    add('hmac.digest', ftype(crypto.hmac, 'digest'))

    if type(crypto.hmac.digest) == 'function' then
        local ok, value = safe(function()
            return crypto.hmac.digest('sha256', HMAC_DATA, HMAC_KEY, true)
        end)
        if ok and type(value) == 'string' then
            add('hmac.digest.raw', 'len:' .. #value .. ',known:' .. (hex(value) == HMAC_SHA256_EXPECT and 'yes' or 'no'))
        else
            add('hmac.digest.raw', ok and ('type:' .. type(value)) or ('error:' .. value))
        end
    end

    if type(crypto.hmac.new) == 'function' then
        local ok, value = safe(function()
            local h = crypto.hmac.new('sha256', HMAC_KEY)
            h:update(HMAC_DATA)
            return h:final(nil, true)
        end)
        if ok and type(value) == 'string' then
            add('hmac.final.nil.true', 'len:' .. #value .. ',known:' .. (hex(value) == HMAC_SHA256_EXPECT and 'yes' or 'no'))
        else
            add('hmac.final.nil.true', ok and ('type:' .. type(value)) or ('error:' .. value))
        end
    end
end

-- Padding-disabled AES tests. TLS record code needs exact block control.
local ZERO16 = string.rep('\0', 16)
local ZERO32 = string.rep('\0', 32)
local AES128_ZERO_BLOCK = '66e94bd4ef8a2c3b884cfa59ca342b2e'

local function probe_exact_cipher(label, name, key, iv)
    local ok, value = safe(function()
        local enc = crypto.encrypt.new(name, key, iv, false)
        local a = enc:update(ZERO16)
        local b = enc:final()
        if b == nil then b = '' end
        return a .. b
    end)
    if ok and type(value) == 'string' then
        add(label, 'ok,len:' .. #value .. ',known:' .. (hex(value) == AES128_ZERO_BLOCK and 'yes' or 'no'))
    else
        add(label, ok and ('type:' .. type(value)) or ('error:' .. value))
    end
end

if crypto.encrypt and type(crypto.encrypt.new) == 'function' then
    probe_exact_cipher('aes128.ecb.padfalse.niliv', 'aes-128-ecb', ZERO16, nil)
    probe_exact_cipher('aes128.cbc.padfalse', 'aes-128-cbc', ZERO16, ZERO16)

    local ok256, value256 = safe(function()
        local enc = crypto.encrypt.new('aes-256-ecb', ZERO32, nil, false)
        local a = enc:update(ZERO16)
        local b = enc:final() or ''
        return a .. b
    end)
    add('aes256.ecb.padfalse.niliv', ok256 and ('ok,len:' .. (type(value256) == 'string' and #value256 or -1)) or ('error:' .. value256))
end

-- NIST AES-128-GCM known-answer test:
-- K=0^128, IV=0^96, P=0^128, AAD=empty
-- C=0388dace60b6a392f328c2b971b2fe78
-- T=ab6e47d42cec13bdf53a67b21257bddf
local GCM_IV = string.rep('\0', 12)
local GCM_CT_EXPECT = '0388dace60b6a392f328c2b971b2fe78'
local GCM_TAG_EXPECT = 'ab6e47d42cec13bdf53a67b21257bddf'

if crypto.encrypt and crypto.decrypt
    and type(crypto.encrypt.new) == 'function'
    and type(crypto.decrypt.new) == 'function' then

    local ok, result = safe(function()
        local enc = crypto.encrypt.new('aes-128-gcm', ZERO16, GCM_IV)
        local update = enc:update(ZERO16)
        local final_ok, finals = pack_returns(function() return enc:final() end)
        return {
            update = update,
            final_ok = final_ok,
            finals = finals
        }
    end)

    if ok and type(result) == 'table' then
        add('gcm.nist.update', 'len:' .. #result.update .. ',cipher-known:' .. (hex(result.update) == GCM_CT_EXPECT and 'yes' or 'no'))
        if result.final_ok then
            describe_returns('gcm.nist.final', result.finals, GCM_TAG_EXPECT)
        else
            add('gcm.nist.final', 'error:' .. tostring(result.finals))
        end
    else
        add('gcm.nist.encrypt', ok and ('type:' .. type(result)) or ('error:' .. result))
    end

    -- Does decrypt accept modified ciphertext without any authentication tag?
    local expected_ct = nil
    local ok_ct, ct = safe(function()
        local enc = crypto.encrypt.new('aes-128-gcm', ZERO16, GCM_IV)
        local c = enc:update(ZERO16)
        local f = enc:final() or ''
        return c .. f
    end)
    if ok_ct and type(ct) == 'string' then expected_ct = ct end

    if expected_ct then
        local ok_dec, dec_info = safe(function()
            local dec = crypto.decrypt.new('aes-128-gcm', ZERO16, GCM_IV)
            local p = dec:update(flip_first_byte(expected_ct))
            local final_ok, finals = pack_returns(function() return dec:final() end)
            return {
                p = p,
                final_ok = final_ok,
                finals = finals
            }
        end)
        if ok_dec and type(dec_info) == 'table' then
            add('gcm.tamper.update', 'len:' .. (type(dec_info.p) == 'string' and #dec_info.p or -1))
            add('gcm.tamper.final.accepted', dec_info.final_ok and 'yes' or 'no')
            if dec_info.final_ok then describe_returns('gcm.tamper.final', dec_info.finals) end
        else
            add('gcm.tamper', ok_dec and ('type:' .. type(dec_info)) or ('error:' .. dec_info))
        end

        -- Feed ciphertext||known-tag as ordinary ciphertext to see whether this binding
        -- implicitly consumes a trailing tag. A 32-byte plaintext result means it does not.
        local function unhex(h)
            local out = {}
            for i = 1, #h, 2 do
                out[#out + 1] = string.char(tonumber(string.sub(h, i, i + 1), 16))
            end
            return table.concat(out)
        end
        local tag = unhex(GCM_TAG_EXPECT)
        local ok_tag, tag_info = safe(function()
            local dec = crypto.decrypt.new('aes-128-gcm', ZERO16, GCM_IV)
            local p = dec:update(expected_ct .. tag)
            local f_ok, finals = pack_returns(function() return dec:final() end)
            return { p = p, f_ok = f_ok, finals = finals }
        end)
        if ok_tag and type(tag_info) == 'table' then
            add('gcm.trailingtag.update', 'len:' .. (type(tag_info.p) == 'string' and #tag_info.p or -1))
            add('gcm.trailingtag.final.accepted', tag_info.f_ok and 'yes' or 'no')
        else
            add('gcm.trailingtag', ok_tag and ('type:' .. type(tag_info)) or ('error:' .. tag_info))
        end
    end
end

local output = table.concat(report, '\n') .. '\n'

function wa_lua_on_flags_cb(ctx)
    return 0
end

function wa_lua_on_handshake_cb(ctx)
    if not sent then
        debug(output)
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
