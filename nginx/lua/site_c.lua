-- site_c.lua
-- C站 (唯一授权入口) - 设备指纹、ECC密钥、签名
-- 功能：提供授权页面，允许前端JS生成密钥对和签名

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

-- 2. Rate limiting
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

-- C站 allows access - the actual auth flow happens in frontend JS
ngx.log(ngx.INFO, "C站 gateway: access granted for IP ", ip)
