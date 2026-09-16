-- Lantern / Shadowrocket crypto capability probe v15.4
-- Hardened diagnostic: callback entry points are installed before any probe work.
-- Public NIST vectors + zero/dummy material only. No Lantern secrets are embedded or printed.

local backend = require 'backend'
local crypto = require 'crypto'

local SUCCESS = backend.RESULT.SUCCESS
local ERROR = backend.RESULT.ERROR
local ctx_free = backend.free
local debug = backend.debug

local emitted = false
local run_probe

-- Install Shadowrocket's expected backend ABI immediately. This mirrors the
-- callback names used by Shadowrocket's public lua-backend examples.
function wa_lua_on_flags_cb(ctx)
    return 0
end

function wa_lua_on_handshake_cb(ctx)
    if not emitted then
        emitted = true
        local ok, result = pcall(run_probe)
        if ok then
            debug(result)
        else
            debug('probe=lantern-crypto-v15.4\nprobe.error=' .. tostring(result) .. '\n')
        end
    end
    -- Diagnostic only: do not claim a completed proxy handshake.
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

local HEX = '0123456789abcdef'

local function tohex(s)
    if type(s) ~= 'string' then return '' end
    local out = {}
    for i = 1, #s do
        local b = string.byte(s, i)
        local hi = math.floor(b / 16)
        local lo = b % 16
        out[#out + 1] = string.sub(HEX, hi + 1, hi + 1)
        out[#out + 1] = string.sub(HEX, lo + 1, lo + 1)
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

local function xor_byte(a, b)
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
    for i = 1, 16 do out[i] = xor_byte(a[i], b[i]) end
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

-- NIST SP 800-38D Algorithm 1, GF(2^128) multiply.
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
            if lsb == 1 then v[1] = xor_byte(v[1], 0xe1) end
        end
    end
    return z
end

local function aes_ecb_block(key, block)
    local alg = (#key == 16) and 'aes-128-ecb' or 'aes-256-ecb'
    local enc = crypto.encrypt.new(alg, key, nil, false)
    local a = enc:update(block)
    local b = enc:final() or ''
    return a .. b
end

local function zero_pad_16(s)
    local rem = #s % 16
    if rem == 0 then return s end
    return s .. string.rep('\0', 16 - rem)
end

local function u64be_bits(nbytes)
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
    for i = 1, n do
        out[i] = string.char(xor_byte(string.byte(a, i), string.byte(b, i)))
    end
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
        cb = inc32(cb)
        pos = pos + 16
    end
    return table.concat(out)
end

local function gcm_seal_96(key, iv12, aad, plaintext)
    assert(#iv12 == 12, 'iv must be 12 bytes')
    local h = aes_ecb_block(key, string.rep('\0', 16))
    local j0 = iv12 .. string.char(0,0,0,1)
    local c = gctr(key, inc32(j0), plaintext)
    local s = ghash(h, aad, c)
    local tag = xor_strings(aes_ecb_block(key, j0), s)
    return c, tag, h
end

run_probe = function()
    local report = {}
    local function add(k, v)
        report[#report + 1] = tostring(k) .. '=' .. tostring(v)
    end

    add('probe', 'lantern-crypto-v15.4')
    add('callback.flags', 'installed')
    add('callback.handshake', 'installed')
    add('callback.read', 'installed')
    add('callback.write', 'installed')
    add('callback.close', 'installed')

    local zero16 = string.rep('\0', 16)
    local zero12 = string.rep('\0', 12)
    local c, tag, h = gcm_seal_96(zero16, zero12, '', zero16)

    add('custom.gcm.h', tohex(h) == '66e94bd4ef8a2c3b884cfa59ca342b2e' and 'known:yes' or ('known:no,' .. tohex(h)))
    add('custom.gcm.cipher', tohex(c) == '0388dace60b6a392f328c2b971b2fe78' and 'known:yes' or ('known:no,' .. tohex(c)))
    add('custom.gcm.tag', tohex(tag) == 'ab6e47d42cec13bdf53a67b21257bddf' and 'known:yes' or ('known:no,' .. tohex(tag)))

    -- Non-empty AAD / multi-block NIST vector.
    local key2 = unhex('feffe9928665731c6d6a8f9467308308')
    local iv2 = unhex('cafebabefacedbaddecaf888')
    local aad2 = unhex('feedfacedeadbeeffeedfacedeadbeefabaddad2')
    local p2 = unhex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39')
    local c2, t2 = gcm_seal_96(key2, iv2, aad2, p2)
    local expect_c2 = '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091'
    local expect_t2 = '5bc94fbc3221a5db94fae95ae7121a47'
    add('custom.gcm.aad.cipher', tohex(c2) == expect_c2 and 'known:yes' or ('known:no,len:' .. #c2))
    add('custom.gcm.aad.tag', tohex(t2) == expect_t2 and 'known:yes' or ('known:no,' .. tohex(t2)))

    -- Reconfirm raw SHA/HMAC behavior in the same hardened load.
    local d = crypto.digest.new('sha256')
    d:update('abc')
    local sha_raw = d:final(nil, true)
    add('sha256.raw', (#sha_raw == 32 and tohex(sha_raw) == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') and 'known:yes' or 'known:no')

    local hm = crypto.hmac.digest('sha256', 'The quick brown fox jumps over the lazy dog', 'key', true)
    add('hmac.sha256.raw', (#hm == 32 and tohex(hm) == 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8') and 'known:yes' or 'known:no')

    return table.concat(report, '\n') .. '\n'
end
