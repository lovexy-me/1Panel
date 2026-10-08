-- 1Panel community WAF engine.
-- Runs in OpenResty (LuaJIT). The config is loaded once per nginx (re)load;
-- the panel reloads nginx after every config change.
local cjson = require "cjson.safe"
local bit = require "bit"

local ngx = ngx
local re_find = ngx.re.find
local str_lower = string.lower
local str_sub = string.sub
local str_find = string.find
local tonumber = tonumber
local ipairs = ipairs
local pairs = pairs
local type = type

local _M = { _VERSION = "1.0" }

local cfg = { enabled = false }
local base_dir
local block_page = "<h1>403 Forbidden</h1>"
local log_file = "/www/cwaf/cwaf.log"

local ip_white_exact, ip_white_cidr = {}, {}
local ip_black_exact, ip_black_cidr = {}, {}
local disabled_hosts = {}
local method_white = {}

-- built-in rule sets, PCRE, matched case-insensitively against decoded input
local RULES = {
    sqli = {
        [[\bunion\b[\s\S]{0,40}?\bselect\b]],
        [[\bselect\b[\s\S]{0,120}?\bfrom\b[\s\S]{0,80}?\b(information_schema|mysql\.user|pg_catalog|sysobjects)\b]],
        [[(\b(sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\s+')]],
        [=[['"`]\s*(or|and|xor)\s+['"`]?\w+['"`]?\s*(=|like|<|>)\s*['"`]?\w+]=],
        [[\b(updatexml|extractvalue|load_file)\s*\(]],
        [[\binto\s+(out|dump)file\b]],
        [[;\s*(drop|truncate)\s+(table|database)\b]],
    },
    xss = {
        [[<\s*script\b]],
        [[\bjavascript\s*:]],
        [[\bon(error|load|mouseover|focus|blur|click|toggle|animationstart|pointerover)\s*=]],
        [[<\s*(iframe|svg|object|embed|base|meta)\b]],
        [[\bdocument\s*\.\s*(cookie|domain|write)\b]],
    },
    traversal = {
        [[(\.\./|\.\.\\)]],
        [[(/etc/(passwd|shadow)|/proc/self/environ|\bwin\.ini\b|boot\.ini)]],
    },
    rce = {
        [[\$\{\s*(jndi|lower|upper|env)\s*:]],
        [[(;|\||`|\$\()\s*(wget|curl|bash|sh|nc|ncat|python[0-9.]*|perl|php)\s]],
        [[\b(phpinfo|system|passthru|shell_exec|proc_open|popen|assert)\s*\(]],
    },
}

local SCANNER_UA = [[(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|zgrab|nuclei|openvas|w3af|hydra|fimap|jaeles)]]
local SENSITIVE_FILE = [[((^|/)\.(git|svn|hg|env|ds_store|htpasswd)(/|$)|\.(sql|bak|swp|old)$|/wp-config\.php.+)]]

local function read_file(p)
    local f = io.open(p, "rb")
    if not f then return nil end
    local d = f:read("*a")
    f:close()
    return d
end

local function ipv4_to_int(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    return ((a * 256 + b) * 256 + c) * 256 + d
end

local function build_ip_set(list)
    local exact, cidr = {}, {}
    for _, item in ipairs(list or {}) do
        if type(item) == "string" and item ~= "" then
            local ip, bits = item:match("^([^/]+)/(%d+)$")
            if ip and ipv4_to_int(ip) then
                bits = tonumber(bits)
                if bits >= 0 and bits <= 32 then
                    local size = 2 ^ (32 - bits)
                    local start = math.floor(ipv4_to_int(ip) / size) * size
                    cidr[#cidr + 1] = { start, start + size - 1 }
                end
            else
                exact[str_lower(item)] = true
            end
        end
    end
    return exact, cidr
end

local function ip_in(ip, exact, cidr)
    if exact[ip] then return true end
    if #cidr == 0 then return false end
    local n = ipv4_to_int(ip)
    if not n then return false end
    for _, r in ipairs(cidr) do
        if n >= r[1] and n <= r[2] then return true end
    end
    return false
end

local function lower_list(list)
    local out = {}
    for _, v in ipairs(list or {}) do
        if type(v) == "string" and v ~= "" then out[#out + 1] = str_lower(v) end
    end
    return out
end

local function contains_any(s, list)
    if not s or s == "" then return nil end
    s = str_lower(s)
    for _, v in ipairs(list) do
        if str_find(s, v, 1, true) then return v end
    end
    return nil
end

function _M.init(dir)
    base_dir = dir
    local raw = read_file(dir .. "/config.json")
    local parsed = raw and cjson.decode(raw)
    if type(parsed) ~= "table" then
        ngx.log(ngx.ERR, "cwaf: config.json missing or invalid, WAF disabled")
        cfg = { enabled = false }
        return
    end
    cfg = parsed
    cfg.cc = type(cfg.cc) == "table" and cfg.cc or {}
    cfg.maxBodyKB = tonumber(cfg.maxBodyKB) or 64
    ip_white_exact, ip_white_cidr = build_ip_set(cfg.ipWhite)
    ip_black_exact, ip_black_cidr = build_ip_set(cfg.ipBlack)
    cfg.urlWhite = lower_list(cfg.urlWhite)
    cfg.urlBlack = lower_list(cfg.urlBlack)
    cfg.uaBlack = lower_list(cfg.uaBlack)
    disabled_hosts = {}
    for _, h in ipairs(lower_list(cfg.disabledHosts)) do disabled_hosts[h] = true end
    method_white = {}
    for _, m in ipairs(cfg.methodWhite or {}) do method_white[string.upper(m)] = true end
    local page = read_file(dir .. "/block.html")
    if page then block_page = page end
    if type(cfg.logFile) == "string" and cfg.logFile ~= "" then log_file = cfg.logFile end
end

function _M.init_worker() end

local function client_ip()
    local hdr = cfg.realIpHeader
    if type(hdr) == "string" and hdr ~= "" then
        local v = ngx.req.get_headers()[hdr]
        if type(v) == "table" then v = v[1] end
        if v and v ~= "" then
            local first = v:match("^%s*([^,%s]+)")
            if first then return str_lower(first) end
        end
    end
    return str_lower(ngx.var.remote_addr or "")
end

local function write_log(ip, host, uri, rule, matched, action)
    local entry = cjson.encode({
        time = ngx.localtime(),
        ip = ip,
        host = host,
        method = ngx.req.get_method(),
        uri = str_sub(uri or "", 1, 512),
        rule = rule,
        match = str_sub(matched or "", 1, 120),
        action = action,
        ua = str_sub(ngx.var.http_user_agent or "", 1, 200),
        id = ngx.var.request_id,
    })
    local f = io.open(log_file, "a")
    if f then
        f:write(entry, "\n")
        f:close()
    end
    local stats = ngx.shared.cwaf_log
    if stats then
        stats:incr("total", 1, 0)
        stats:incr("rule:" .. rule, 1, 0)
    end
end

local function deny(ip, host, uri, rule, matched)
    local observe = cfg.mode == "observe"
    write_log(ip, host, uri, rule, matched, observe and "log" or "block")
    if observe then return end
    if rule == "cc" then
        ngx.status = 429
    else
        ngx.status = 403
    end
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    local body = block_page:gsub("{{id}}", ngx.var.request_id or "")
    ngx.say(body)
    return ngx.exit(ngx.status)
end

local function match_rules(value, names)
    if not value or value == "" then return nil end
    for _, name in ipairs(names) do
        for _, pattern in ipairs(RULES[name]) do
            local from, to = re_find(value, pattern, "ijo")
            if from then
                return name, str_sub(value, from, to)
            end
        end
    end
    return nil
end

local function check_args(args, names, depth)
    depth = depth or 0
    if depth > 3 then return nil end
    for k, v in pairs(args) do
        if type(k) == "string" then
            local r, m = match_rules(k, names)
            if r then return r, m end
        end
        if type(v) == "string" then
            local r, m = match_rules(v, names)
            if r then return r, m end
        elseif type(v) == "table" then
            local r, m = check_args(v, names, depth + 1)
            if r then return r, m end
        end
    end
    return nil
end

local function cc_check(ip)
    local cc = cfg.cc
    if not cc.enabled then return false end
    local dict = ngx.shared.cwaf_limit
    if not dict then return false end
    if dict:get("b:" .. ip) then return true end
    local window = tonumber(cc.window) or 60
    local limit = tonumber(cc.requests) or 300
    local count = dict:incr("c:" .. ip, 1, 0, window)
    if count and count > limit then
        dict:set("b:" .. ip, true, tonumber(cc.blockSeconds) or 600)
        return true
    end
    return false
end

function _M.access()
    if not cfg.enabled then return end
    local host = str_lower(ngx.var.host or "")
    if disabled_hosts[host] then return end

    local ip = client_ip()
    if ip_in(ip, ip_white_exact, ip_white_cidr) then return end
    local uri = ngx.var.request_uri or "/"
    local path = ngx.var.uri or "/"

    if ip_in(ip, ip_black_exact, ip_black_cidr) then
        return deny(ip, host, uri, "ipBlack", ip)
    end
    if contains_any(uri, cfg.urlWhite) then return end

    if next(method_white) and not method_white[ngx.req.get_method()] then
        return deny(ip, host, uri, "method", ngx.req.get_method())
    end
    if cc_check(ip) then
        return deny(ip, host, uri, "cc", ip)
    end
    local hit = contains_any(uri, cfg.urlBlack)
    if hit then return deny(ip, host, uri, "urlBlack", hit) end

    local ua = ngx.var.http_user_agent or ""
    hit = contains_any(ua, cfg.uaBlack)
    if hit then return deny(ip, host, uri, "uaBlack", hit) end
    if cfg.scanner then
        local from, to = re_find(ua, SCANNER_UA, "ijo")
        if from then return deny(ip, host, uri, "scanner", str_sub(ua, from, to)) end
    end
    if cfg.sensitiveFile then
        local from, to = re_find(path, SENSITIVE_FILE, "ijo")
        if from then return deny(ip, host, uri, "sensitiveFile", str_sub(path, from, to)) end
    end

    local names = {}
    for _, n in ipairs({ "sqli", "xss", "traversal", "rce" }) do
        if cfg[n] then names[#names + 1] = n end
    end
    if #names == 0 then return end

    local r, m = match_rules(ngx.unescape_uri(path), names)
    if r then return deny(ip, host, uri, r, m) end
    local args = ngx.req.get_uri_args(100)
    r, m = check_args(args, names)
    if r then return deny(ip, host, uri, r, m) end
    local cookie = ngx.var.http_cookie
    if cookie then
        r, m = match_rules(ngx.unescape_uri(cookie), names)
        if r then return deny(ip, host, uri, r, m) end
    end

    if cfg.bodyCheck then
        local method = ngx.req.get_method()
        if method == "POST" or method == "PUT" or method == "PATCH" then
            local len = tonumber(ngx.var.content_length or "0") or 0
            local ctype = str_lower(ngx.var.content_type or "")
            if len > 0 and len <= cfg.maxBodyKB * 1024 and not str_find(ctype, "multipart/", 1, true) then
                ngx.req.read_body()
                local body = ngx.req.get_body_data()
                if body then
                    if str_find(ctype, "application/x-www-form-urlencoded", 1, true) then
                        local post = ngx.req.get_post_args(100)
                        r, m = check_args(post, names)
                    else
                        r, m = match_rules(body, names)
                    end
                    if r then return deny(ip, host, uri, r, m) end
                end
            end
        end
    end
end

_M._test = { build_ip_set = build_ip_set, ip_in = ip_in, RULES = RULES, base_dir = function() return base_dir end }
return _M
