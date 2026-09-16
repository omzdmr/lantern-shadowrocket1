-- Lantern / Shadowrocket crypto capability probe v15.3
-- Verifies that TLS 1.2 AES-GCM can be implemented safely in Lua even though
-- Shadowrocket's exposed GCM binding does not expose/verify authentication tags.
-- Public NIST vectors + zero/dummy material only. No Lantern secrets are embedded.

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

local function unhex(h)
    local out = {}
    for i = 1, #h, 2 do
        out[#out + 1] = string.char(tonumber(string.sub(h, i, i + 1), 16))
    end
    return table.concat(out)
end

local function safe(fn)
    local ok, a = pcall(fn)
    if ok then return true, a end
    return false, tostring(a)
end

-- Detect Lua 5.3+ native integer bitwise operators without placing them directly
-- in this source file (older parsers would reject the file before execution).
local native_bxor = nil
local native_band = nil
local native_rshift = nil
local native_lshift = nil

if type(load) == 'function' then
    local ok, factory = pcall(load, 'return function(a,b) return a ~ b end, function(a,b) return a & b end, function(a,b) return a >> b end, function(a,b) return a << b end')
    if ok and type(factory) == 'function' then
        local ok2, bx, ba, rs, ls = pcall(factory)
        if ok2 then
            native_bxor, native_band, native_rshift, native_lshift = bx, ba, rs, ls
        end
    end
end

add('probe', 'lantern-crypto-v15.3')
add('native.bitwise', native_bxor and 'yes' or 'no')

local function xor_byte_slow(a, b)
    local out = 0
    local p = 1
    for _ = 1, 8 do
        local aa = a % 2
        local bb = b % 2
        if aa ~= bb then out = out + p end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        p = p * 2
    end
    return out
end

local function bxor8(a, b)
    if native_bxor then return native_band(native_bxor(a, b), 0xff) end
    return xor_byte_slow(a, b)
end

local function bytes16(s)
    local t = {}
    for i = 1, 16 do t[i] = string.byte(s, i) or 0 end
    return t
end

local function str16(t)
    return string.char(
        t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8],
        t[9], t[10], t[11], t[12], t[13], t[14], t[15], t[16]
    )
end

local function xor128(a, b)
    local out = {}
    for i = 1, 16 do out[i] = bxor8(a[i], b[i]) end
    return out
end

local function rshift1(v)
    local out = {}
    local carry = 0
    for i = 1, 16 do
        local b = v[i]
        out[i] = math.floor(b / 2) + carry
        carry = (b % 2) * 128
    end
    return out
end

-- GHASH field multiply in GF(2^128), SP 800-38D Algorithm 1.
local function gf_mul(x, y)
    local z = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
    local v = {}
    for i = 1, 16 do v[i] = y[i] end

    for byte_i = 1, 16 do
        local xb = x[byte_i]
        for bit_i = 7, 0, -1 do
            local bit = math.floor(xb / (2 ^ bit_i)) % 2
            if bit == 1 then z = xor128(z, v) end

            local lsb = v[16] % 2
            v = rshift1(v)
            if lsb == 1 then v[1] = bxor8(v[1], 0xe1) end
        end
    end
    return z
end

local function aes_ecb_block(key, block)
    local enc = crypto.encrypt.new(#key == 16 and 'aes-128-ecb' or 'aes-256-ecb', key, nil, false)
    local out = enc:update(block)
    local tail = enc:final() or ''
    return out .. tail
end

local function zero_pad_16(s)
    local rem = #s % 16
    if rem == 0 then return s end
    return s .. string.rep('\0', 16 - rem)
end

local function u64be_bits(nbytes)
    -- Probe inputs are deliberately small, so exact integer arithmetic is safe here.
    local bits = nbytes * 8
    local out = {}
    for i = 8, 1, -1 do
        out[i] = string.char(bits % 256)
        bits = math.floor(bits / 256)
    end
    return table.concat(out)
end

local function ghash(h, aad, ciphertext)
    local y = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
    local hs = bytes16(h)
    local data = zero_pad_16(aad) .. zero_pad_16(ciphertext) .. u64be_bits(#aad) .. u64be_bits(#ciphertext)

    for pos = 1, #data, 16 do
        local block = bytes16(string.sub(data, pos, pos + 15))
        y = gf_mul(xor128(y, block), hs)
    end
    return str16(y)
end

local function inc32(block)
    local b = {string.byte(block, 1, 16)}
    for i = 16, 13, -1 do
        b[i] = b[i] + 1
        if b[i] <= 255 then break end
        b[i] = 0
    end
    return string.char(
        b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8],
        b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16]
    )
end

local function xor_strings(a, b)
    local out = {}
    local n = math.min(#a, #b)
    for i = 1, n do out[i] = string.char(bxor8(string.byte(a, i), string.byte(b, i))) end
    return table.concat(out)
end

local function gctr(key, icb, input)
    if #input == 0 then return '' end
    local cb = icb
    local out = {}
    local pos = 1
    while pos <= #input do
        local block = string.sub(input, pos, pos + 15)
        local stream = aes_ecb_block(key, cb)
        out[#out + 1] = xor_strings(block, string.sub(stream, 1, #block))
        pos = pos + 16
        cb = inc32(cb)
    end
    return table.concat(out)
end

local function gcm_seal_96(key, iv12, aad, plaintext)
    assert(#iv12 == 12, 'only 96-bit IV used in this probe')
    local h = aes_ecb_block(key, string.rep('\0', 16))
    local j0 = iv12 .. string.char(0,0,0,1)
    local ciphertext = gctr(key, inc32(j0), plaintext)
    local s = ghash(h, aad, ciphertext)
    local tag = xor_strings(aes_ecb_block(key, j0), s)
    return ciphertext, tag, h
end

-- NIST SP 800-38D Test Case 2:
-- K = 0^128, IV = 0^96, P = 0^128, AAD = empty
-- C = 0388dace60b6a392f328c2b971b2fe78
-- T = ab6e47d42cec13bdf53a67b21257bddf
local ZERO16 = string.rep('\0', 16)
local ZERO12 = string.rep('\0', 12)
local EXPECT_H = '66e94bd4ef8a2c3b884cfa59ca342b2e'
local EXPECT_C = '0388dace60b6a392f328c2b971b2fe78'
local EXPECT_T = 'ab6e47d42cec13bdf53a67b21257bddf'

local ok_nist, nist = safe(function()
    local c, t, h = gcm_seal_96(ZERO16, ZERO12, '', ZERO16)
    return {c=c, t=t, h=h}
end)

if ok_nist and type(nist) == 'table' then
    add('custom.gcm.h', hex(nist.h) == EXPECT_H and 'known:yes' or ('known:no,' .. hex(nist.h)))
    add('custom.gcm.cipher', hex(nist.c) == EXPECT_C and 'known:yes' or ('known:no,' .. hex(nist.c)))
    add('custom.gcm.tag', hex(nist.t) == EXPECT_T and 'known:yes' or ('known:no,' .. hex(nist.t)))
else
    add('custom.gcm.nist', 'error:' .. tostring(nist))
end

-- Verify non-empty AAD + multi-block path against a public NIST vector.
-- K=feffe9928665731c6d6a8f9467308308
-- IV=cafebabefacedbaddecaf888
-- AAD=feedfacedeadbeeffeedfacedeadbeefabaddad2
-- P=d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
--   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
-- Expected C below and tag=5bc94fbc3221a5db94fae95ae7121a47
local KEY2 = unhex('feffe9928665731c6d6a8f9467308308')
local IV2 = unhex('cafebabefacedbaddecaf888')
local AAD2 = unhex('feedfacedeadbeeffeedfacedeadbeefabaddad2')
local P2 = unhex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39')
local C2 = '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091'
local T2 = '5bc94fbc3221a5db94fae95ae7121a47'

local ok_nist2, nist2 = safe(function()
    local c, t = gcm_seal_96(KEY2, IV2, AAD2, P2)
    return {c=c, t=t}
end)

if ok_nist2 and type(nist2) == 'table' then
    add('custom.gcm.aad.cipher', hex(nist2.c) == C2 and 'known:yes' or ('known:no,len:' .. #nist2.c))
    add('custom.gcm.aad.tag', hex(nist2.t) == T2 and 'known:yes' or ('known:no,' .. hex(nist2.t)))
else
    add('custom.gcm.aad', 'error:' .. tostring(nist2))
end

-- TLS helpers feasibility: exact big-endian packing and constant-time-ish tag compare primitives.
add('string.pack', type(string.pack))
local ok_pack, packed = safe(function() return string.pack('>I2I4', 0x0303, 0x01020304) end)
add('pack.be', ok_pack and (hex(packed) == '030301020304' and 'known:yes' or ('known:no,' .. hex(packed))) or ('error:' .. tostring(packed)))

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
