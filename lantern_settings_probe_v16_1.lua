-- Shadowrocket Lua settings-capacity probe v16.1
-- Logs only setting names and value lengths. It never logs the values themselves.

local backend = require 'backend'

local SUCCESS = backend.RESULT.SUCCESS
local ERROR = backend.RESULT.ERROR
local free = backend.free
local debug = backend.debug

local emitted = false

local function safe_len(v)
    if v == nil then return 0 end
    local s = tostring(v)
    return #s
end

local function emit_report()
    local rows = { 'probe=lantern-settings-v16.1' }
    local keys = {}
    for k, _ in pairs(settings or {}) do
        keys[#keys + 1] = tostring(k)
    end
    table.sort(keys)
    for _, k in ipairs(keys) do
        local ok, v = pcall(function() return settings[k] end)
        if ok then
            rows[#rows + 1] = 'settings.' .. k .. '.len=' .. tostring(safe_len(v))
        else
            rows[#rows + 1] = 'settings.' .. k .. '.error=1'
        end
    end

    -- Common aliases are included explicitly in case the settings object does not enumerate them.
    local common = {
        'username','user','name','password','method','host','server','address','port',
        'tls','peer','sni','plugin','file','path','script','remarks','remark','title','description','debug'
    }
    local seen = {}
    for _, k in ipairs(keys) do seen[k] = true end
    for _, k in ipairs(common) do
        if not seen[k] then
            local ok, v = pcall(function() return settings and settings[k] end)
            if ok and v ~= nil then
                rows[#rows + 1] = 'settings.' .. k .. '.len=' .. tostring(safe_len(v))
            end
        end
    end

    debug(table.concat(rows, '\n') .. '\n')
end

function wa_lua_on_flags_cb(ctx)
    return 0
end

function wa_lua_on_handshake_cb(ctx)
    if not emitted then
        emitted = true
        local ok, err = pcall(emit_report)
        if not ok then
            debug('probe=lantern-settings-v16.1\nprobe.error=' .. tostring(err) .. '\n')
        end
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
    free(ctx)
    return SUCCESS
end
