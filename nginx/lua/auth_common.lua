-- auth_common.lua
-- Shared utilities for the auth gateway

local _M = {}

-- Redis connection
local redis = require "resty.redis"

function _M.get_redis()
    local red = redis:new()
    red:set_timeout(2000)
    local ok, err = red:connect("127.0.0.1", 6379)
    if not ok then
        return nil, "redis connect failed: " .. (err or "unknown")
    end
    return red
end

function _M.release_redis(red)
    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        ngx.log(ngx.ERR, "redis keepalive failed: ", err)
    end
end

-- Get client IP
function _M.get_client_ip()
    return ngx.var.http_x_real_ip
        or ngx.var.http_x_forwarded_for
        or ngx.var.remote_addr
        or "0.0.0.0"
end

-- Check IP blacklist
function _M.is_blacklisted(ip)
    local red, err = _M.get_redis()
    if not red then return false end
    
    local res, err = red:sismember("auth:ip:black", ip)
    _M.release_redis(red)
    
    return res == 1
end

-- Check IP whitelist
function _M.is_whitelisted(ip)
    local red, err = _M.get_redis()
    if not red then return false end
    
    local res, err = red:sismember("auth:ip:white", ip)
    _M.release_redis(red)
    
    return res == 1
end

-- Rate limiting (fixed window)
function _M.check_rate_limit(ip)
    local red, err = _M.get_redis()
    if not red then return true, 0 end
    
    local key = "auth:ip:limit:" .. ip
    local current = tonumber(red:get(key)) or 0
    local max_req = 30
    local window = 60
    
    if current >= max_req then
        local ttl = red:ttl(key)
        _M.release_redis(red)
        return false, ttl > 0 and ttl or 1
    end
    
    red:incr(key)
    if current == 0 then
        red:expire(key, window)
    end
    
    _M.release_redis(red)
    return true, max_req - current - 1
end

-- Set secure cookie
function _M.set_session_cookie(session_id)
    local cookie = string.format(
        "auth_sid=%s; Path=/; Max-Age=86400; Secure; HttpOnly; SameSite=Strict",
        session_id
    )
    ngx.header["Set-Cookie"] = cookie
end

-- Get session cookie
function _M.get_session_cookie()
    local cookie = ngx.var.cookie_auth_sid
    return cookie
end

-- Validate session directly from Redis (no HTTP needed)
function _M.validate_session(session_id, fingerprint)
    if not session_id then
        return false, "no session"
    end
    
    local red, err = _M.get_redis()
    if not red then
        return false, "redis unavailable"
    end
    
    local val = red:get("session:" .. session_id)
    _M.release_redis(red)
    
    if not val or val == ngx.null then
        return false, "session not found or expired"
    end
    
    local cjson = require "cjson.safe"
    local session = cjson.decode(val)
    if not session then
        return false, "session data corrupt"
    end
    
    -- Fingerprint check (strict mode)
    if fingerprint and session.fingerprint and fingerprint ~= session.fingerprint then
        return false, "fingerprint mismatch"
    end
    
    return true, session
end

-- JSON response helper
function _M.json_response(status, data)
    local cjson = require "cjson.safe"
    ngx.status = status
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.header["X-Content-Type-Options"] = "nosniff"
    ngx.header["X-Frame-Options"] = "DENY"
    ngx.say(cjson.encode(data))
    ngx.exit(status)
end

return _M
