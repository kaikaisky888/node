-- site_a.lua
-- A站 (核心业务站) - 裸访拦截
-- 功能：无Token/会话直接403，Token核销，会话校验

local auth = require "auth_common"

-- Get request path
local uri = ngx.var.uri

-- Skip auth check for static assets
if uri:match("%.(css|js|png|jpg|gif|ico|svg|woff|woff2|ttf)$") then
    return
end

-- Get session cookie
local session_id = auth.get_session_cookie()

-- Get device fingerprint from header (if present)
local fingerprint = ngx.var.http_x_device_fingerprint

-- Check if has valid session
if session_id then
    local valid, data = auth.validate_session(session_id, fingerprint)
    if valid then
        ngx.log(ngx.INFO, "A站: valid session for ", session_id:sub(1, 8) .. "...")
        return  -- Allow access
    end
end

-- No valid session - serve 403 error page
ngx.status = 403
ngx.header["Content-Type"] = "text/html; charset=utf-8"
local f = io.open("/workspace/projects/frontend/errors/403.html", "r")
if f then
    ngx.say(f:read("*a"))
    f:close()
else
    ngx.say('<html><body><h1>403 Access Denied</h1><p>Please visit <a href="https://c.okok.cfd/">C Site</a> to authorize.</p></body></html>')
end
ngx.exit(403)
