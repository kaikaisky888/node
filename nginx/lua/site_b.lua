-- site_b.lua
-- B站 (鉴权中转层) - Lua全量拦截
-- 功能：IP限流、黑名单检查、签名校验、Token签发代理

local auth = require "auth_common"

-- Get client IP
local ip = auth.get_client_ip()

-- 1. Check blacklist
if auth.is_blacklisted(ip) then
    auth.json_response(403, {
        success = false,
        error = "IP blocked"
    })
end

-- 2. Rate limiting (skip for whitelisted IPs)
if not auth.is_whitelisted(ip) then
    local allowed, retry_after = auth.check_rate_limit(ip)
    if not allowed then
        ngx.header["Retry-After"] = tostring(retry_after)
        auth.json_response(429, {
            success = false,
            error = "Rate limit exceeded",
            retry_after = retry_after
        })
    end
end

-- 3. For token generation requests, proxy to PHP auth service
-- The actual signature verification happens in PHP
-- Lua just does the pre-filtering above

ngx.log(ngx.INFO, "B站 gateway: passed pre-filter for IP ", ip)
