-- Lantern TLS 1.2 session-resumption + SMUX v1 backend for Shadowrocket
-- Generic: no Lantern secrets embedded.
-- settings.user     = <sni>|<sessionTicketBase64>
-- settings.password = <masterSecretBase64(64 chars)><authToken(64 chars)>
-- Shadowrocket TLS MUST be OFF; this Lua implements TLS itself.

local backend = require 'backend'
local crypto = require 'crypto'

local SUCCESS   = backend.RESULT.SUCCESS
local ERROR     = backend.RESULT.ERROR
local HANDSHAKE = backend.RESULT.HANDSHAKE

local get_uuid = backend.get_uuid
local get_host = backend.get_address_host
local get_port = backend.get_address_port
local write_upstream = backend.write
local free = backend.free
local debug = backend.debug

local rand = crypto.rand

local TLS12 = string.char(0x03, 0x03)
local CIPHER = 0xc02b
local REC_CCS = 20
local REC_ALERT = 21
local REC_HANDSHAKE = 22
local REC_APP = 23

local SMUX_VERSION = 1
local CMD_SYN = 0
local CMD_FIN = 1
local CMD_PSH = 2
local CMD_NOP = 3
local STREAM_ID = 1
local MAX_SMUX_PAYLOAD = 32768
local MAX_TLS_PLAINTEXT = 16384

local states = {}

local function u16be(n)
    return string.char(math.floor(n / 256) % 256, n % 256)
end

local function u24be(n)
    return string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
end

local function u16le(n)
    return string.char(n % 256, math.floor(n / 256) % 256)
end

local function u32le(n)
    local b1 = n % 256
    n = math.floor(n / 256)
    local b2 = n % 256
    n = math.floor(n / 256)
    local b3 = n % 256
    n = math.floor(n / 256)
    local b4 = n % 256
    return string.char(b1, b2, b3, b4)
end

local function read_u16be(s, i)
    local a, b = string.byte(s, i, i + 1)
    if not a or not b then return nil end
    return a * 256 + b
end

local function read_u24be(s, i)
    local a, b, c = string.byte(s, i, i + 2)
    if not a or not b or not c then return nil end
    return a * 65536 + b * 256 + c
end

local function read_u16le(s, i)
    local a, b = string.byte(s, i, i + 1)
    if not a or not b then return nil end
    return a + b * 256
end

local function read_u32le(s, i)
    local a, b, c, d = string.byte(s, i, i + 3)
    if not a or not b or not c or not d then return nil end
    return a + b * 256 + c * 65536 + d * 16777216
end

local function seq64be(n)
    local out = {}
    for i = 8, 1, -1 do
        out[i] = string.char(n % 256)
        n = math.floor(n / 256)
    end
    return table.concat(out)
end

local function consteq(a, b)
    if type(a) ~= 'string' or type(b) ~= 'string' or #a ~= #b then return false end
    local diff = 0
    for i = 1, #a do
        local x, y = string.byte(a, i), string.byte(b, i)
        if x ~= y then diff = 1 end
    end
    return diff == 0
end

local B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local B64MAP = {}
for i = 1, #B64 do B64MAP[string.sub(B64, i, i)] = i - 1 end

local function b64decode(s)
    if type(s) ~= 'string' then return nil, 'not-string' end
    s = s:gsub('%s+', '')
    if (#s % 4) ~= 0 then return nil, 'bad-length' end
    local out = {}
    for i = 1, #s, 4 do
        local c1 = string.sub(s, i, i)
        local c2 = string.sub(s, i + 1, i + 1)
        local c3 = string.sub(s, i + 2, i + 2)
        local c4 = string.sub(s, i + 3, i + 3)
        local a, b = B64MAP[c1], B64MAP[c2]
        local c = (c3 == '=') and 0 or B64MAP[c3]
        local d = (c4 == '=') and 0 or B64MAP[c4]
        if a == nil or b == nil or c == nil or d == nil then return nil, 'bad-char' end
        local n = a * 262144 + b * 4096 + c * 64 + d
        out[#out + 1] = string.char(math.floor(n / 65536) % 256)
        if c3 ~= '=' then out[#out + 1] = string.char(math.floor(n / 256) % 256) end
        if c4 ~= '=' then out[#out + 1] = string.char(n % 256) end
    end
    return table.concat(out)
end

local function xor_byte(a, b)
    local out, p = 0, 1
    for _ = 1, 8 do
        local aa, bb = a % 2, b % 2
        if aa ~= bb then out = out + p end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        p = p * 2
    end
    return out
end

local function xor_strings(a, b)
    local out = {}
    local n = math.min(#a, #b)
    for i = 1, n do
        out[i] = string.char(xor_byte(string.byte(a, i), string.byte(b, i)))
    end
    return table.concat(out)
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
    local enc = crypto.encrypt.new('aes-128-ecb', key, nil, false)
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
    local h = aes_ecb_block(key, string.rep('\0', 16))
    local j0 = iv12 .. string.char(0,0,0,1)
    local c = gctr(key, inc32(j0), plaintext)
    local s = ghash(h, aad, c)
    local tag = xor_strings(aes_ecb_block(key, j0), s)
    return c, tag
end

local function gcm_open_96(key, iv12, aad, ciphertext, tag)
    local h = aes_ecb_block(key, string.rep('\0', 16))
    local j0 = iv12 .. string.char(0,0,0,1)
    local s = ghash(h, aad, ciphertext)
    local expected = xor_strings(aes_ecb_block(key, j0), s)
    if not consteq(expected, tag) then return nil, 'bad-gcm-tag' end
    return gctr(key, inc32(j0), ciphertext)
end

local function hmac_sha256(key, data)
    return crypto.hmac.digest('sha256', data, key, true)
end

local function sha256(data)
    local d = crypto.digest.new('sha256')
    d:update(data)
    return d:final(nil, true)
end

local function tls_prf(secret, label, seed, n)
    local fullseed = label .. seed
    local a = hmac_sha256(secret, fullseed)
    local out = {}
    local got = 0
    while got < n do
        local block = hmac_sha256(secret, a .. fullseed)
        out[#out + 1] = block
        got = got + #block
        a = hmac_sha256(secret, a)
    end
    return string.sub(table.concat(out), 1, n)
end

local function ext(t, body)
    return u16be(t) .. u16be(#body) .. body
end

local function handshake_msg(t, body)
    return string.char(t) .. u24be(#body) .. body
end

local function tls_record(t, body)
    return string.char(t) .. TLS12 .. u16be(#body) .. body
end

local function build_client_hello(st)
    st.client_random = rand.bytes(32)

    local suites = table.concat({
        u16be(0xc02b), u16be(0xc02f), u16be(0xc02c), u16be(0xc030),
        u16be(0xcca9), u16be(0xcca8), u16be(0xc013), u16be(0xc014),
        u16be(0x009c), u16be(0x009d), u16be(0x002f), u16be(0x0035)
    })

    local sni_name = st.sni
    local sni_list = string.char(0) .. u16be(#sni_name) .. sni_name
    local sni = u16be(#sni_list) .. sni_list

    local groups = u16be(6) .. u16be(29) .. u16be(23) .. u16be(24)
    local points = string.char(1, 0)
    local sigalgs = u16be(10) .. u16be(0x0403) .. u16be(0x0804) .. u16be(0x0401) .. u16be(0x0503) .. u16be(0x0805)

    local extensions = table.concat({
        ext(0, sni),
        ext(10, groups),
        ext(11, points),
        ext(13, sigalgs),
        ext(23, ''),
        ext(35, st.ticket),
        ext(0xff01, string.char(0))
    })

    local body = TLS12 .. st.client_random ..
                 string.char(0) ..
                 u16be(#suites) .. suites ..
                 string.char(1, 0) ..
                 u16be(#extensions) .. extensions

    local hs = handshake_msg(1, body)
    st.transcript = hs
    return tls_record(REC_HANDSHAKE, hs)
end

local function derive_keys(st)
    if st.keys_ready then return true end
    if not st.server_random or not st.client_random then return false end
    local kb = tls_prf(st.master_secret, 'key expansion', st.server_random .. st.client_random, 40)
    st.client_key = string.sub(kb, 1, 16)
    st.server_key = string.sub(kb, 17, 32)
    st.client_iv = string.sub(kb, 33, 36)
    st.server_iv = string.sub(kb, 37, 40)
    st.client_seq = 0
    st.server_seq = 0
    st.keys_ready = true
    return true
end

local function seal_record(st, typ, plaintext)
    local seq = st.client_seq or 0
    local explicit = seq64be(seq)
    local iv12 = st.client_iv .. explicit
    local aad = seq64be(seq) .. string.char(typ) .. TLS12 .. u16be(#plaintext)
    local c, tag = gcm_seal_96(st.client_key, iv12, aad, plaintext)
    st.client_seq = seq + 1
    return tls_record(typ, explicit .. c .. tag)
end

local function open_record(st, typ, fragment)
    if #fragment < 24 then return nil, 'short-gcm-record' end
    local seq = st.server_seq or 0
    local explicit = string.sub(fragment, 1, 8)
    local c = string.sub(fragment, 9, #fragment - 16)
    local tag = string.sub(fragment, #fragment - 15)
    local iv12 = st.server_iv .. explicit
    local aad = seq64be(seq) .. string.char(typ) .. TLS12 .. u16be(#c)
    local p, err = gcm_open_96(st.server_key, iv12, aad, c, tag)
    if not p then return nil, err end
    st.server_seq = seq + 1
    return p
end

local function smux_frame(cmd, sid, payload)
    payload = payload or ''
    return string.char(SMUX_VERSION, cmd) .. u16le(#payload) .. u32le(sid) .. payload
end

local function smux_data(payload)
    if not payload or #payload == 0 then return '' end
    local out = {}
    local pos = 1
    while pos <= #payload do
        local last = math.min(pos + MAX_SMUX_PAYLOAD - 1, #payload)
        out[#out + 1] = smux_frame(CMD_PSH, STREAM_ID, string.sub(payload, pos, last))
        pos = last + 1
    end
    return table.concat(out)
end

local function target_for(ctx)
    local host = get_host(ctx)
    local port = get_port(ctx)
    if string.find(host, ':', 1, true) and string.sub(host, 1, 1) ~= '[' then host = '[' .. host .. ']' end
    return host .. ':' .. tostring(port)
end

local function connect_request(ctx, st)
    local target = target_for(ctx)
    return 'CONNECT ' .. target .. ' HTTP/1.1\r\n' ..
           'Host: ' .. target .. '\r\n' ..
           'Proxy-Connection: Keep-Alive\r\n' ..
           'User-Agent: Go-http-client/1.1\r\n' ..
           'X-Lantern-Auth-Token: ' .. st.auth_token .. '\r\n' ..
           'X-Lantern-Version: 7.6.179\r\n' ..
           'X-Lantern-Platform: android\r\n' ..
           'X-Lantern-Time-Zone: Asia/Shanghai\r\n' ..
           '\r\n'
end

local function tls_wrap_app(st, plaintext)
    if not plaintext or #plaintext == 0 then return '' end
    local out = {}
    local pos = 1
    while pos <= #plaintext do
        local last = math.min(pos + MAX_TLS_PLAINTEXT - 1, #plaintext)
        out[#out + 1] = seal_record(st, REC_APP, string.sub(plaintext, pos, last))
        pos = last + 1
    end
    return table.concat(out)
end

local function parse_smux(st, incoming)
    st.smux_raw = st.smux_raw .. (incoming or '')
    local payloads = {}
    local saw_fin = false
    while #st.smux_raw >= 8 do
        local ver = string.byte(st.smux_raw, 1)
        local cmd = string.byte(st.smux_raw, 2)
        local len = read_u16le(st.smux_raw, 3)
        local sid = read_u32le(st.smux_raw, 5)
        local total = 8 + len
        if #st.smux_raw < total then break end
        local payload = len > 0 and string.sub(st.smux_raw, 9, total) or ''
        st.smux_raw = string.sub(st.smux_raw, total + 1)
        if ver ~= SMUX_VERSION then return nil, 'smux-version-' .. tostring(ver) end
        if cmd == CMD_NOP then
        elseif sid == STREAM_ID then
            if cmd == CMD_PSH then
                if #payload > 0 then payloads[#payloads + 1] = payload end
            elseif cmd == CMD_FIN then
                saw_fin = true
            end
        end
    end
    return table.concat(payloads), nil, saw_fin
end

local function send_smux_connect(ctx, st)
    local initial = smux_frame(CMD_SYN, STREAM_ID, '') .. smux_data(connect_request(ctx, st))
    write_upstream(ctx, tls_wrap_app(st, initial))
    st.smux_started = true
    debug('lantern-v16.2 tls-resume=ok smux=sent\n')
end

local function handle_smux_plain(ctx, st, plain)
    local stream_bytes, err, saw_fin = parse_smux(st, plain)
    if err then return nil, err, false end

    if not st.proxy_established then
        if stream_bytes and #stream_bytes > 0 then st.connect_buf = st.connect_buf .. stream_bytes end
        local p = string.find(st.connect_buf, '\r\n\r\n', 1, true)
        if not p then
            if saw_fin then return nil, 'smux-fin-before-connect', false end
            return '', nil, false
        end
        local header = string.sub(st.connect_buf, 1, p + 3)
        local code = tonumber(string.match(header, '^HTTP/%d+%.%d+%s+(%d+)') or '0')
        if code < 200 or code >= 300 then return nil, 'connect-http-' .. tostring(code), false end
        st.proxy_established = true
        local tail = string.sub(st.connect_buf, p + 4)
        st.connect_buf = ''
        debug('lantern-v16.2 connect=ok\n')
        return tail, nil, true
    end

    if saw_fin and (not stream_bytes or #stream_bytes == 0) then return nil, 'smux-fin', false end
    return stream_bytes or '', nil, false
end

local function parse_server_hello(st, body)
    if #body < 38 then return nil, 'short-server-hello' end
    local ver = string.sub(body, 1, 2)
    if ver ~= TLS12 then return nil, 'server-version' end
    st.server_random = string.sub(body, 3, 34)
    local sidlen = string.byte(body, 35)
    local p = 36 + sidlen
    if #body < p + 2 then return nil, 'short-server-hello-fields' end
    local cipher = read_u16be(body, p)
    if cipher ~= CIPHER then return nil, 'cipher-' .. tostring(cipher) end
    if not derive_keys(st) then return nil, 'key-derive' end
    return true
end

local function handle_plain_handshakes(st, bytes)
    st.hs_raw = st.hs_raw .. bytes
    while #st.hs_raw >= 4 do
        local typ = string.byte(st.hs_raw, 1)
        local len = read_u24be(st.hs_raw, 2)
        local total = 4 + len
        if #st.hs_raw < total then break end
        local msg = string.sub(st.hs_raw, 1, total)
        local body = string.sub(st.hs_raw, 5, total)
        st.hs_raw = string.sub(st.hs_raw, total + 1)

        if typ == 2 then
            local ok, err = parse_server_hello(st, body)
            if not ok then return nil, err end
            st.saw_server_hello = true
            st.transcript = st.transcript .. msg
        elseif typ == 4 then
            st.transcript = st.transcript .. msg
        else
            return nil, 'resume-rejected-handshake-' .. tostring(typ)
        end
    end
    return true
end

local function finish_tls(ctx, st, finished_msg)
    if #finished_msg < 16 or string.byte(finished_msg, 1) ~= 20 then return nil, 'expected-server-finished' end
    local len = read_u24be(finished_msg, 2)
    if len ~= 12 or #finished_msg ~= 16 then return nil, 'bad-server-finished-length' end
    local got = string.sub(finished_msg, 5, 16)
    local expected = tls_prf(st.master_secret, 'server finished', sha256(st.transcript), 12)
    if not consteq(got, expected) then return nil, 'server-finished-mismatch' end

    st.transcript = st.transcript .. finished_msg
    local verify = tls_prf(st.master_secret, 'client finished', sha256(st.transcript), 12)
    local client_finished = handshake_msg(20, verify)

    write_upstream(ctx, tls_record(REC_CCS, string.char(1)) .. seal_record(st, REC_HANDSHAKE, client_finished))
    st.tls_established = true
    send_smux_connect(ctx, st)
    return true
end

local function parse_material()
    local user = tostring((settings and settings.user) or '')
    local password = tostring((settings and settings.password) or '')
    local sni, ticket_b64 = string.match(user, '^([^|]+)|(.+)$')
    if not sni or not ticket_b64 then return nil, 'user-format' end
    if #password < 128 then return nil, 'password-length-' .. tostring(#password) end

    local master_b64 = string.sub(password, 1, 64)
    local auth = string.sub(password, 65, 128)
    local ticket, e1 = b64decode(ticket_b64)
    if not ticket then return nil, 'ticket-b64-' .. tostring(e1) end
    local master, e2 = b64decode(master_b64)
    if not master then return nil, 'master-b64-' .. tostring(e2) end
    if #master ~= 48 then return nil, 'master-length-' .. tostring(#master) end
    if #auth ~= 64 then return nil, 'auth-length-' .. tostring(#auth) end

    return {sni=sni, ticket=ticket, master_secret=master, auth_token=auth}
end

local material, material_error = parse_material()
local init_logged = false

local function new_state(ctx)
    local st = {
        sent_client_hello = false,
        tls_raw = '',
        hs_raw = '',
        transcript = '',
        server_cipher_on = false,
        tls_established = false,
        smux_started = false,
        smux_raw = '',
        connect_buf = '',
        proxy_established = false,
        failed = false
    }
    if material then
        st.sni = material.sni
        st.ticket = material.ticket
        st.master_secret = material.master_secret
        st.auth_token = material.auth_token
    end
    states[get_uuid(ctx)] = st
    return st
end

local function get_state(ctx)
    return states[get_uuid(ctx)] or new_state(ctx)
end

local function fail(st, why)
    if not st.failed then
        st.failed = true
        debug('lantern-v16.2 error=' .. tostring(why) .. '\n')
    end
    return ERROR, nil
end

function wa_lua_on_flags_cb(ctx)
    get_state(ctx)
    return 0
end

function wa_lua_on_handshake_cb(ctx)
    local st = get_state(ctx)
    if st.proxy_established then return true end
    if material_error then return false end

    if not init_logged then
        init_logged = true
        debug('lantern-v16.2 material ticketLen=' .. tostring(#st.ticket) .. ' masterLen=' .. tostring(#st.master_secret) .. ' authLen=' .. tostring(#st.auth_token) .. ' sni=' .. tostring(st.sni) .. '\n')
    end

    if not st.sent_client_hello then
        local hello = build_client_hello(st)
        write_upstream(ctx, hello)
        st.sent_client_hello = true
        debug('lantern-v16.2 clienthello=sent\n')
    end
    return false
end

function wa_lua_on_read_cb(ctx, buf)
    local st = get_state(ctx)
    if material_error then return fail(st, material_error) end
    st.tls_raw = st.tls_raw .. (buf or '')

    local output = {}
    local became_proxy = false

    while #st.tls_raw >= 5 do
        local typ = string.byte(st.tls_raw, 1)
        local ver = string.sub(st.tls_raw, 2, 3)
        local len = read_u16be(st.tls_raw, 4)
        local total = 5 + len
        if #st.tls_raw < total then break end
        local fragment = string.sub(st.tls_raw, 6, total)
        st.tls_raw = string.sub(st.tls_raw, total + 1)

        if ver ~= TLS12 then return fail(st, 'record-version') end

        if not st.server_cipher_on then
            if typ == REC_HANDSHAKE then
                local ok, err = handle_plain_handshakes(st, fragment)
                if not ok then return fail(st, err) end
            elseif typ == REC_CCS then
                if fragment ~= string.char(1) then return fail(st, 'bad-ccs') end
                if not st.saw_server_hello or not st.keys_ready then return fail(st, 'ccs-before-serverhello') end
                st.server_cipher_on = true
                st.server_seq = 0
            elseif typ == REC_ALERT then
                return fail(st, 'plaintext-alert-' .. tostring(string.byte(fragment, 1) or -1) .. '-' .. tostring(string.byte(fragment, 2) or -1))
            else
                return fail(st, 'unexpected-plaintext-record-' .. tostring(typ))
            end
        else
            local plain, err = open_record(st, typ, fragment)
            if not plain then return fail(st, err) end

            if not st.tls_established then
                if typ ~= REC_HANDSHAKE then return fail(st, 'expected-encrypted-finished-record-' .. tostring(typ)) end
                local ok, ferr = finish_tls(ctx, st, plain)
                if not ok then return fail(st, ferr) end
            else
                if typ == REC_APP then
                    local app, aerr, became = handle_smux_plain(ctx, st, plain)
                    if aerr then return fail(st, aerr) end
                    if app and #app > 0 then output[#output + 1] = app end
                    if became then became_proxy = true end
                elseif typ == REC_ALERT then
                    return fail(st, 'encrypted-alert-' .. tostring(string.byte(plain, 1) or -1) .. '-' .. tostring(string.byte(plain, 2) or -1))
                elseif typ == REC_HANDSHAKE then
                else
                    return fail(st, 'unexpected-encrypted-record-' .. tostring(typ))
                end
            end
        end
    end

    local joined = table.concat(output)
    if became_proxy then
        return HANDSHAKE, (#joined > 0) and joined or nil
    end
    if st.proxy_established then
        return SUCCESS, (#joined > 0) and joined or nil
    end
    return SUCCESS, nil
end

function wa_lua_on_write_cb(ctx, buf)
    local st = get_state(ctx)
    if not st.proxy_established or not st.tls_established then return SUCCESS, nil end
    local framed = smux_data(buf)
    return SUCCESS, tls_wrap_app(st, framed)
end

function wa_lua_on_close_cb(ctx)
    local id = get_uuid(ctx)
    local st = states[id]
    if st and st.proxy_established and st.tls_established then
        pcall(function()
            local fin = smux_frame(CMD_FIN, STREAM_ID, '')
            write_upstream(ctx, tls_wrap_app(st, fin))
        end)
    end
    states[id] = nil
    free(ctx)
    return SUCCESS
end
