-- OpenLiteWaf — 极简 Nginx Lua WAF
-- CC 防御 + 常见攻击特征拦截（SQL 注入 / XSS / 路径穿越 / 命令执行 / 探测扫描），
-- 触发时返回 403 红色极简警告页；提供公开安全统计页（/security）：
-- 实时拦截趋势图、类别分布、来源 IP Top（脱敏）、攻击日志分页（最近 500 条）、
-- 当前封禁 IP 近似计数。
-- 文档与集成方式见 OpenLiteWaf/README.md。

local _M = { _VERSION = "1.1.0" }

local cjson = require "cjson.safe"

-- ───────────────────────── 配置 ─────────────────────────
local CONFIG = {
    -- shared dict 名称，须与 nginx.conf 中 lua_shared_dict 一致
    dict_name = "openlitewaf",
    -- 公开统计页前缀：跳过特征匹配（仍受 CC 限流），HTML 为前缀本身，JSON 为前缀 + /stats 与 /logs
    stats_prefix = "/security",
    -- 完全白名单前缀：跳过所有检查（ACME HTTP-01 等）
    whitelist_prefixes = {
        "/.well-known/acme-challenge/",
    },
    -- 请求体检查豁免前缀：日志内容端点的 body 是用户日志原文，
    -- 任意文本命中攻击特征属正常业务（如分享安全日志），交由应用层输出转义防护。
    body_exempt_prefixes = {
        "/v1/log",
        "/1/log",
    },
    -- CC 防御：window 秒内超过 limit 次请求即封禁该 IP ban 秒。
    -- 注意：须低于 nginx limit_req 静态限速，否则超额请求会先被 limit_req 以 503 丢弃，轮不到封禁。
    cc = { window = 10, limit = 240, ban = 600 },
    -- 命中攻击特征后的封禁秒数
    sig_ban = 600,
    -- 攻击日志容量（环形槽位，最新覆盖最旧）
    log_capacity = 500,
    -- 攻击日志每页条数
    log_page_size = 50,
    -- 封禁槽位数：shared dict 无法枚举键，用环形槽位记录封禁到期时间，
    -- 活跃封禁 IP 数为近似值（槽位被同 IP 重复封禁覆盖时可能低估）
    ban_slots = 1024,
    -- 请求体扫描：只读前 body_scan_limit 字节（payload 几乎总在开头）；
    -- Content-Length 超过 body_size_limit 的请求直接跳过（大文件上传）
    body_scan_limit = 65536,
    body_size_limit = 2 * 1024 * 1024,
    -- 趋势图统计的分钟数（分钟桶 TTL 两倍于该值自动回收）
    trend_minutes = 60,
    -- 统计页展示的来源 IP Top 数
    top_ips = 8,
    -- 攻击日志单字段（URI / UA）最大长度
    log_field_max = 160,
}

-- ─────────── 攻击特征规则（PCRE，语法同 ngx.re）───────────
-- 按顺序匹配，命中即停。类目：sqli / xss / traversal / rce / probe。
-- 匹配对象依次为：原始 request_uri、完整解码 request_uri（含 query）、
-- 规范化 uri、User-Agent、请求体（及其一次 URL 解码）。
-- RULES-BEGIN（tmp/ 下的 PHP 回归测试按此格式解析）
_M.RULES = {
    -- SQL 注入
    { "sqli",     [[union\s+(all\s+)?select]] },
    { "sqli",     [[\b(or|and)\s+\d+\s*=\s*\d+]] },
    { "sqli",     [['\s*(or|and)\s*']] },
    { "sqli",     [[\bsleep\s*\(]] },
    { "sqli",     [[\bbenchmark\s*\(\s*\d]] },
    { "sqli",     [[\bwaitfor\s+delay]] },
    { "sqli",     [[\bxp_cmdshell\b]] },
    { "sqli",     [[\bexec\s+sp_\w+]] },
    { "sqli",     [[@@version]] },
    { "sqli",     [[information_schema]] },
    { "sqli",     [[\bload_file\s*\(]] },
    { "sqli",     [[\bextractvalue\s*\(]] },
    { "sqli",     [[\bupdatexml\s*\(]] },
    { "sqli",     [[\bconcat\s*\(]] },
    { "sqli",     [[into\s+(out|dump)file]] },
    { "sqli",     [[\b(drop|truncate)\s+table\b]] },
    { "sqli",     [[\bselect\s+[\w*,\s`'%]+\s+from\s+]] },
    -- XSS
    { "xss",      [[<\s*script\b]] },
    { "xss",      [[<\s*/\s*script]] },
    { "xss",      [[javascript\s*:]] },
    { "xss",      [[\bon(error|load|click|mouseover|focus|blur|input|submit)\s*=]] },
    { "xss",      [[<\s*(iframe|embed|object|svg)\b]] },
    { "xss",      [[document\s*\.\s*(cookie|write|location)]] },
    { "xss",      [[\balert\s*\(\s*\d*\)]] },
    { "xss",      [[data\s*:\s*text/html]] },
    { "xss",      [[vbscript\s*:]] },
    { "xss",      [[\bsrcdoc\s*=]] },
    { "xss",      [[\beval\s*\(]] },
    { "xss",      [[fromcharcode]] },
    -- 路径穿越（原始与解码形态均覆盖）
    { "traversal",[[(\.\./)+]] },
    { "traversal",[[\.\.\\]] },
    { "traversal",[[%2e%2e(%2f|%5c|/)]] },
    { "traversal",[[/etc/(passwd|shadow|hosts)]] },
    { "traversal",[[(boot|win)\.ini]] },
    -- 命令 / 代码执行（RCE）
    { "rce",      [[\bwhoami\b]] },
    { "rce",      [==[\buname\s+-[a-z]]==] },
    { "rce",      [[;\s*(cat|ls|uname|whoami|wget|curl|nc|bash|sh|ping|nslookup)\b]] },
    { "rce",      [[\|\s*(cat|ls|uname|whoami|wget|curl|nc|bash|sh|ping)\b]] },
    { "rce",      [[\$\(\s*(cat|ls|id|whoami|uname|curl|wget|ping)\b]] },
    { "rce",      [[`[^`]{0,120}`]] },
    { "rce",      [[\bnc\s+-e\b]] },
    { "rce",      [[\b(ba|z)?sh\s+-i\b]] },
    { "rce",      [[\b(wget|curl)\s+(https?|ftp)]] },
    { "rce",      [[\b(system|passthru|shell_exec|proc_open|popen)\s*\(]] },
    { "rce",      [[\bbase64_decode\s*\(]] },
    { "rce",      [[/proc/self/environ]] },
    -- 探测 / 扫描路径（本站无 PHP/JSP 等动态文件与运维后台，出现即视为探测）
    { "probe",    [[\.php(\?|$)]] },
    { "probe",    [[\.(asp|aspx|jsp|jspx)(\?|$)]] },
    { "probe",    [[/(\.env|\.git|\.svn|\.hg|\.DS_Store|\.htaccess|\.htpasswd)(/|\?|$)]] },
    { "probe",    [[/(\.aws|\.ssh|\.docker)(/|$)]] },
    { "probe",    [[phpmyadmin]] },
    { "probe",    [[wp-(admin|login|content|config|includes|json)]] },
    { "probe",    [[/actuator(/|\?|$)]] },
    { "probe",    [[/cgi-bin/]] },
    { "probe",    [[^/admin(\?|$)]] },
    { "probe",    [[/id_rsa(\?|$)]] },
    { "probe",    [[\.(sql|bak|backup|old|ini|conf|cfg|log|yml|yaml|json|xml)(\?|$|(?![\w.]))]] },
    { "probe",    [[/backup(/|\?|$)]] },
    { "probe",    [[/server-status]] },
    { "probe",    [[/(druid|nacos|jenkins|solr)(/|\?|$)]] },
    { "probe",    [[/manager/html]] },
    { "probe",    [[/debug/vars]] },
    -- 扫描器 / 攻击工具 User-Agent
    { "probe",    [[\b(sqlmap|nikto|nmap|masscan|zgrab|zmap|gobuster|dirbuster|dirb|dirsearch|feroxbuster|wpscan|acunetix|netsparker|nessus|openvas|arachni|havij|sqlninja|wfuzz|ffuf|nuclei|xray|afrog|whatweb|subfinder|(?<!python-)httpx|naabu|amass|arjun|wafw00f|hydra)\b]] },
}
-- RULES-END

-- ───────────────────── 拦截页模板：卡片组件（无完整页面外壳，支持 iframe 嵌入）─────────────
-- 布局样式挂在根 #waf-block 上（而非 body），同一份响应体既可独立渲染，
-- 也可由前端在 iframe 中展示。charset 由 deny() 的 Content-Type 头保证。
local WARN_HTML = [==[
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
body{margin:0;display:flex;justify-content:center}
.widget{max-width:560px;width:100%;padding:28px 28px 24px;background:#fff;border:1px solid rgba(226,232,240,.6);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
.row-main{display:flex;align-items:center;gap:20px}
.icon-triangle{flex-shrink:0;display:flex;align-items:center;justify-content:center;line-height:0}
.icon-triangle svg{width:56px;height:56px;display:block}
.text-group{display:flex;flex-direction:column;gap:6px}
.title{font-size:26px;font-weight:600;color:#0f172a;line-height:1.3;letter-spacing:-.01em}
.title .highlight{color:#ea580c;font-weight:700}
.sub{font-size:16px;font-weight:400;color:#334155;line-height:1.5}
.sub .brand{font-weight:600;color:#1e293b}
.sub .brand strong{color:#ea580c;font-weight:700}
.sub a{color:inherit;text-decoration:none;cursor:pointer}
.sub a:hover{opacity:.6}
@media (max-width:480px){.widget{padding:16px 14px 14px}.row-main{gap:12px}.icon-triangle svg{width:36px;height:36px}.title{font-size:19px}.sub{font-size:12px}}
@media (max-width:380px){.widget{padding:14px 10px 12px}.row-main{gap:10px;align-items:flex-start}.icon-triangle svg{width:30px;height:30px}.title{font-size:17px}.sub{font-size:11px}}
</style>
<div class="widget">
  <div class="row-main">
      <div class="icon-triangle" role="img" aria-label="OpenLiteWaf">
        <svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect x="1" y="1" width="62" height="62" rx="14" fill="#ea580c" />
          <rect x="8" y="23" width="13" height="18" rx="6.5" stroke="#fff" stroke-width="3.2" />
          <path d="M27 23v17h11" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" />
          <path d="M43 23l3 17 3.5-11 3.5 11 3-17" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </div>
    <div class="text-group">
      <div class="title">{{TITLE}}</div>
      <div class="sub"><span class="brand">安全与性能由<strong>OpenLiteWaf</strong></span> 提供。被误封了？<a href="mailto:lyl518@outlook.com">联系管理员</a>。</div>
    </div>
  </div>
</div>
]==]

-- ───────────────────── 内部工具 ─────────────────────
local function dict() return ngx.shared[CONFIG.dict_name] end

local function bump(d, name)
    d:incr("c:" .. name, 1, 0)
end

local function starts_with(s, prefix)
    return prefix ~= "" and s ~= nil and s:sub(1, #prefix) == prefix
end

-- 模板替换工具：gsub 的 replacement 中 % 是转义符，统一转义后注入，
-- 防止动态值（如未来引入含 % 的 reason）破坏模板
local function tpl_replace(tpl, key, value)
    return tpl:gsub(key, (tostring(value):gsub("%%", "%%%%")))
end

local function whitelisted(uri)
    for _, p in ipairs(CONFIG.whitelist_prefixes) do
        if starts_with(uri, p) then return true end
    end
    return false
end

local function skip_signature(uri)
    -- 与 nginx location = 精确匹配语义一致；前缀匹配会让 /security<任意后缀>
    -- 绕过特征检查（S1），故仅豁免统计页自身的三个精确 URI
    return uri == CONFIG.stats_prefix
        or uri == CONFIG.stats_prefix .. "/stats"
        or uri == CONFIG.stats_prefix .. "/logs"
end

-- IP 脱敏：公开统计页不展示完整 IP（隐私约定），IPv4 留前两段、IPv6 留前三组
local function mask_ip(ip)
    if not ip or ip == "" then return "?" end
    if ip:find(":", 1, true) then
        local groups = {}
        for g in ip:gmatch("[0-9a-fA-F]+") do groups[#groups + 1] = g end
        return table.concat(groups, ":", 1, math.min(3, #groups)) .. "::*"
    end
    local head = ip:match("^(%d+%.%d+)%.")
    return head and (head .. ".*.*") or "?"
end

-- ngx.re.compile 是 lua-resty-core（resty.core.re）的 FFI API，不是
-- lua-nginx-module 的原生 API：resty.core 未加载时 ngx.re 表里只有原生的
-- find/match/gmatch，compile 为 nil。这里主动加载（官方镜像自带），
-- 加载失败也不影响功能——get_rules() 会检测并走纯字符串匹配路径。
-- pcall 包裹：require 失败不能炸掉 access 阶段。
pcall(require, "resty.core.re")

-- 编译后的规则缓存（worker 级，惰性）：ngx.re.compile 不能在 init_by_lua（master 进程）
-- 阶段调用，必须在请求阶段首次用时编译；每个 worker 各自缓存一份。
local compiled_rules

-- compile 是否可用（模块加载时探测一次；resty.core.re 加载成功后为 function）
local COMPILE_AVAILABLE = type(ngx.re.compile) == "function"

local function get_rules()
    if not compiled_rules then
        -- compile 不可用（resty.core 缺失）：直接走 _M.RULES 字符串路径，
        -- ngx.re.find 是原生 API，必然存在——绝不能在 compile 为 nil 时调用它
        if not COMPILE_AVAILABLE then
            return _M.RULES
        end
        compiled_rules = {}
        for i, rule in ipairs(_M.RULES) do
            local re, err = ngx.re.compile(rule[2], "ji")
            if not re then
                -- 规则非法：警告并降级到 ngx.re.find 字符串缓存路径（沿用 "ijo"）
                ngx.log(ngx.WARN, "[OpenLiteWaf] invalid rule #" .. i .. " ("
                    .. rule[1] .. "): " .. tostring(err) .. "; fallback to string cache")
                compiled_rules = nil
                return _M.RULES
            end
            compiled_rules[i] = { rule[1], re }
        end
    end
    return compiled_rules
end

-- 对单个 subject 顺序匹配规则，返回命中类目或 nil。
-- 惰性编译优先走正则对象（减缓存查找），非法规则自动回退字符串缓存路径。
local function match_rules(subject)
    if not subject or subject == "" then return nil end
    local rules = get_rules()
    for _, rule in ipairs(rules) do
        local matcher = rule[2]
        local hit
        if type(matcher) == "table" then
            hit = matcher:find(subject)
        else
            hit = ngx.re.find(subject, matcher, "ijo")
        end
        if hit then return rule[1] end
    end
    return nil
end

-- 测试可见性：暴露编译缓存状态，logic 回归测试用它断言"init 阶段不编译、
-- 首个请求完成惰性编译"的时序。生产代码不应依赖此访问器。
function _M._rules_compiled()
    return compiled_rules
end

-- ───────────── 攻击日志 / 趋势 / 封禁槽位（shared dict）─────────────
-- shared dict 不支持键枚举，环形槽位是唯一的无锁写入方案：
-- 全局序号 incr 定槽，读端按序号回溯；同槽覆盖即自然淘汰最旧数据。

-- 写入一条攻击日志（URI 中 token 参数打码，防止泄露到公开统计页）
local function log_attack(d, category)
    local seq = d:incr("log_seq", 1, 0) or 0
    local uri = ngx.var.request_uri or ngx.var.uri or "-"
    uri = uri:gsub("([?&]token=)[^&]*", "%1***")
    local entry = {
        t = math.floor(ngx.now()),
        cat = category,
        ip = mask_ip(ngx.var.remote_addr),
        u = uri:sub(1, CONFIG.log_field_max),
        a = (ngx.var.http_user_agent or "-"):sub(1, CONFIG.log_field_max),
    }
    local ok, json = pcall(cjson.encode, entry)
    if ok and json then
        d:set("log:" .. (seq - 1) % CONFIG.log_capacity, json)
    end
end

-- 分钟级拦截计数（趋势图数据源），TTL 两倍统计窗口自动回收。
-- 已知窗口：shared dict 无原子 incr+expire，incr 建键（无 TTL）与 expire 之间
-- worker 异常退出会留下不过期键；该键随 nginx reload/master 重启清理，概率极低，
-- 接受此固有窗口（openresty shared dict 惯用法的固有限制）。
local function bump_trend(d)
    local bucket = math.floor(ngx.now() / 60)
    local key = "m:" .. bucket
    if (d:incr(key, 1, 0) or 0) == 1 then
        d:expire(key, CONFIG.trend_minutes * 120)
    end
end

-- 记录一次新封禁的到期时间（活跃封禁数的近似数据源）
local function record_ban_slot(d, ttl)
    local seq = d:incr("ban_seq", 1, 0) or 0
    d:set("bs:" .. (seq - 1) % CONFIG.ban_slots, ngx.now() + ttl)
    bump(d, "banned")
end

-- 当前活跃封禁数（近似）：遍历槽位统计未到期的封禁
local function count_active_bans(d)
    local now = ngx.now()
    local n = 0
    for i = 0, CONFIG.ban_slots - 1 do
        local exp = d:get("bs:" .. i)
        if exp and exp > now then n = n + 1 end
    end
    return n
end

-- 按页读取攻击日志（最新在前）
local function collect_logs(d, page)
    local seq = d:get("log_seq") or 0
    local total = math.min(seq, CONFIG.log_capacity)
    local per = CONFIG.log_page_size
    local pages = math.max(1, math.ceil(total / per))
    page = math.floor(tonumber(page) or 1)
    if page < 1 then page = 1 end
    if page > pages then page = pages end
    local logs = {}
    if total > 0 then
        local start_idx = seq - (page - 1) * per
        for i = 0, per - 1 do
            local idx = start_idx - i
            if idx < 1 then break end
            local raw = d:get("log:" .. (idx - 1) % CONFIG.log_capacity)
            if raw then
                local ok, e = pcall(cjson.decode, raw)
                if ok and type(e) == "table" then logs[#logs + 1] = e end
            end
        end
    end
    return { total = total, page = page, pages = pages, per_page = per, logs = logs }
end

-- 从最近日志聚合来源 IP Top（已脱敏）
local function top_from_logs(d, limit)
    local seq = d:get("log_seq") or 0
    local total = math.min(seq, CONFIG.log_capacity)
    local counts, ips = {}, {}
    for i = 0, total - 1 do
        local raw = d:get("log:" .. (seq - i - 1) % CONFIG.log_capacity)
        if raw then
            local ok, e = pcall(cjson.decode, raw)
            if ok and type(e) == "table" and e.ip then
                if counts[e.ip] == nil then
                    counts[e.ip] = 0
                    ips[#ips + 1] = e.ip
                end
                counts[e.ip] = counts[e.ip] + 1
            end
        end
    end
    table.sort(ips, function(a, b) return counts[a] > counts[b] end)
    local out = {}
    for i = 1, math.min(limit or CONFIG.top_ips, #ips) do
        out[#out + 1] = { ip = ips[i], n = counts[ips[i]] }
    end
    return out
end

-- ───────────────────── 请求体检查 ─────────────────────
-- 仅对有 body 的方法启用；Content-Length 超限（大文件上传）直接跳过。
-- 读取量限制在 body_scan_limit：payload 几乎总在开头，避免整包扫描的内存/IO 代价。
-- 日志内容端点（body_exempt_prefixes）豁免：用户日志原文命中特征属正常业务。
-- chunked 请求没有 Content-Length，不能凭 cl == 0 提前放行，否则形成整体绕过；
-- 实际扫描量统一由 body_scan_limit 控制（内存段或落盘文件头部）。
local function read_body_data(uri)
    if not ngx.req then return nil end
    local method = (ngx.req.get_method and ngx.req.get_method()) or ngx.var.request_method
    if method ~= "POST" and method ~= "PUT" and method ~= "PATCH" then return nil end
    for _, p in ipairs(CONFIG.body_exempt_prefixes) do
        if starts_with(uri, p) then return nil end
    end
    local cl = tonumber(ngx.var.http_content_length or "") or 0
    -- Content-Length 超限（大文件上传）快速跳过；无 Content-Length（chunked）继续走读取路径
    if cl > CONFIG.body_size_limit then return nil end
    pcall(function() ngx.req.read_body() end)
    local data = ngx.req.get_body_data()
    if not data and ngx.req.get_body_file then
        -- body 超出 client_body_buffer_size 落盘时，读文件前 N 字节
        local file = ngx.req.get_body_file()
        if file then
            local ok, content = pcall(function()
                local f = io.open(file, "rb")
                if not f then return nil end
                local head = f:read(CONFIG.body_scan_limit)
                f:close()
                return head
            end)
            data = ok and content or nil
        end
    end
    return data
end

local function deny(d, category)
    bump(d, "blocked")
    if category then
        bump(d, category)
        log_attack(d, category)
        bump_trend(d)
    end
    -- 服务端审计日志（含 IP，仅入 nginx error log，不影响统计页隐私约定）
    ngx.log(ngx.WARN, "[OpenLiteWaf] block ip=", ngx.var.remote_addr or "?",
        " rule=", category or "ban", " uri=", ngx.var.uri or "-")
    -- 标题按拦截状态区分：特征命中 / CC 频率 / 封禁期。高亮词随文案变化。
    local title
    if category == "cc" then
        title = '您的请求<span class="highlight">频率过高</span>。'
    elseif category == nil then
        title = '您的访问已被<span class="highlight">临时封禁</span>。'
    else
        title = '我们认为您的请求是<span class="highlight">恶意</span>的。'
    end
    local page = tpl_replace(WARN_HTML, "{{TITLE}}", title)
    ngx.status = 403
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.say(page)
    -- 官方推荐写法：状态码与响应体已发送后，用 ngx.exit(ngx.HTTP_OK) 结束整个请求，
    -- 避免 nginx 默认错误页覆盖自定义警告页。
    return ngx.exit(ngx.HTTP_OK)
end

-- ───────────────────── 生命周期 ─────────────────────
-- init_by_lua：master 进程初始化，仅记录启动时间（shared dict 全 worker 共享）。
-- 规则编译保持惰性（首个请求时按 worker 完成）：ngx.re.compile 依赖 resty.core.re，
-- 模块顶部已 pcall 加载；即便加载失败，get_rules() 也会走纯字符串匹配路径，
-- 不会因 compile 缺失而中止 access 阶段（历史 bug：曾导致线上完全不拦截）。
function _M.init()
    local d = dict()
    if d and not d:get("c:start_epoch") then
        d:set("c:start_epoch", ngx.now())
    end
end

-- access_by_lua：每个请求的检查入口
function _M.access()
    local d = dict()
    if not d then return end  -- shared dict 未配置时直接放行，不阻塞业务

    local uri = ngx.var.uri or "/"

    -- 完全白名单：不计入、不检查
    if whitelisted(uri) then return end
    bump(d, "total")

    local ip = ngx.var.remote_addr or "unknown"

    -- 封禁名单检查（CC 与特征命中共用）
    if d:get("b:" .. ip) then
        return deny(d, nil)
    end

    -- CC 防御：固定窗口计数（键按窗口分桶，TTL 两倍窗口自动回收）
    local window = CONFIG.cc.window
    local bucket = math.floor(ngx.now() / window)
    local key = "r:" .. ip .. ":" .. bucket
    local n = d:incr(key, 1, 0)
    if n == 1 then
        d:expire(key, window * 2)
    end
    if n and n > CONFIG.cc.limit then
        d:set("b:" .. ip, 1, CONFIG.cc.ban)
        record_ban_slot(d, CONFIG.cc.ban)
        return deny(d, "cc")
    end

    -- 统计页自身：跳过特征匹配，避免规则误伤公开页
    if skip_signature(uri) then return end

    -- 特征匹配 subject，实际顺序为：原始 request_uri（抓 %2e%2e 等编码特征）→
    -- 规范化 uri → User-Agent → 完整解码 request_uri（含 query，修复 %20 不匹配
    -- \s 的绕过）→ 请求体 → 请求体的一次 URL 解码。规则"命中即停"，
    -- 同一 payload 命中多类时归入先匹配到的类目。
    local subjects = { ngx.var.request_uri, uri, ngx.var.http_user_agent }
    local req_uri = ngx.var.request_uri
    if req_uri and req_uri ~= "" then
        local decoded = ngx.unescape_uri(req_uri)
        if decoded ~= req_uri then subjects[#subjects + 1] = decoded end
    end
    local body = read_body_data(uri)
    if body then
        subjects[#subjects + 1] = body
        local decoded = ngx.unescape_uri(body)
        if decoded ~= body then subjects[#subjects + 1] = decoded end
    end

    for _, subject in ipairs(subjects) do
        local category = match_rules(subject)
        if category then
            d:set("b:" .. ip, 1, CONFIG.sig_ban)
            record_ban_slot(d, CONFIG.sig_ban)
            return deny(d, category)
        end
    end
end

-- ───────────────────── 公开统计页 ─────────────────────
local STATS_HTML = [==[<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenLiteWaf 安全统计</title>
<style>
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"PingFang SC",sans-serif;max-width:860px;margin:2.25rem auto 3rem;padding:0 1.25rem;color:#23272e;background:#f5f6f8;-webkit-font-smoothing:antialiased}
header{display:flex;align-items:flex-end;justify-content:space-between;gap:.8rem;flex-wrap:wrap;margin-bottom:1.6rem}
h1{font-size:1.3rem;font-weight:700;margin:0;letter-spacing:.01em}
.cards{display:grid;grid-template-columns:repeat(2,1fr);gap:.8rem}
.card{background:#fff;border:1px solid #e6e8eb;border-radius:10px;padding:.9rem 1.05rem .85rem;box-shadow:0 1px 2px rgba(16,24,40,.04)}
.card span{display:block;font-size:.72rem;color:#8a919c;letter-spacing:.02em}
.card b{display:block;margin-top:.35rem;font-size:1.45rem;font-weight:650;font-variant-numeric:tabular-nums;letter-spacing:-.01em;color:#b42318}
.card.muted b{color:#23272e}
h2{display:flex;align-items:center;gap:.7rem;font-size:.8rem;font-weight:600;color:#66707c;margin:2.1rem 0 .75rem;letter-spacing:.04em}
h2::after{content:"";flex:1;height:1px;background:#e6e8eb}
h2 small{font-weight:400;font-size:.72rem;color:#98a1ab;letter-spacing:0}
.panel{background:#fff;border:1px solid #e6e8eb;border-radius:10px;padding:1.05rem 1.1rem;box-shadow:0 1px 2px rgba(16,24,40,.04)}
#trend rect{transition:opacity .15s}
#trend rect:hover{opacity:1}
.barrow{display:flex;align-items:center;gap:.8rem;margin:.55rem 0;font-size:.78rem}
.barrow .lbl{width:8em;color:#3f4750;flex-shrink:0}
.barrow .lbl.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.barrow .track{flex:1;height:8px;background:#f0f2f4;border-radius:999px;overflow:hidden}
.bar{display:block;height:100%;background:#d64545;border-radius:999px;min-width:2px}
.barrow .num{min-width:3.5em;text-align:right;font-variant-numeric:tabular-nums;color:#23272e}
.tablewrap{background:#fff;border:1px solid #e6e8eb;border-radius:10px;box-shadow:0 1px 2px rgba(16,24,40,.04);overflow:hidden}
table{border-collapse:collapse;width:100%}
th,td{padding:.5rem .8rem;text-align:left;border-bottom:1px solid #f1f3f5;font-size:.78rem;word-break:break-all;vertical-align:top}
th{color:#8a919c;font-weight:600;font-size:.72rem;background:#fafbfc;letter-spacing:.03em}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:#fafbfc}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap;color:#66707c}
.tag{display:inline-block;padding:.08rem .5rem;border-radius:999px;font-size:.7rem;background:#fdf1f0;color:#b42318;border:1px solid #f2cdca}
.pager{display:flex;gap:.7rem;align-items:center;justify-content:center;margin:.9rem 0}
.pager button{font:inherit;font-size:.78rem;padding:.3rem .95rem;border:1px solid #d5d9de;background:#fff;border-radius:999px;color:#3f4750;cursor:pointer;transition:border-color .15s,background .15s}
.pager button:hover:not(:disabled){border-color:#b6bcc4;background:#fafbfc}
.pager button:disabled{color:#c3c9d0;border-color:#e6e8eb;cursor:default}
.pager .info{font-size:.74rem;color:#8a919c}
footer{margin-top:2rem;padding-top:1rem;border-top:1px solid #e6e8eb;color:#98a1ab;font-size:.73rem;line-height:1.7}
.noscript{color:#b42318;font-size:.85rem}
.empty{color:#a3aab3;font-size:.82rem;padding:1.2rem 0;text-align:center}
@media (max-width:520px){body{margin-top:1.25rem;padding:0 .9rem}h1{font-size:1.1rem}.card b{font-size:1.25rem}th,td{padding:.45rem .6rem}}
@media (min-width:640px){.cards{grid-template-columns:repeat(3,1fr)}}
</style>
</head>
<body>
<header>
  <div>
    <h1>OpenLiteWaf 安全统计</h1>
  </div>
</header>

<div class="cards">
  <div class="card muted"><span>累计请求</span><b id="st-req">–</b></div>
  <div class="card"><span>已拦截请求</span><b id="st-blocked">–</b></div>
  <div class="card"><span>拦截率</span><b id="st-ratio">–</b></div>
  <div class="card"><span>最近 60 分钟拦截</span><b id="st-60m">–</b></div>
  <div class="card"><span>拦截速率（次/分钟）</span><b id="st-rate">–</b></div>
  <div class="card muted"><span>当前封禁 IP（近似）</span><b id="st-active">–</b></div>
</div>

<h2>最近 60 分钟拦截趋势</h2>
<div class="panel" id="trend"><div class="empty">加载中…</div></div>

<h2>拦截类别分布</h2>
<div class="panel" id="cats"><div class="empty">加载中…</div></div>

<h2>攻击来源 IP Top <small>最近 500 条 · 已脱敏</small></h2>
<div class="panel" id="topips"><div class="empty">加载中…</div></div>

<h2>攻击日志 <small>最近 500 条 · 每页 50 条</small></h2>
<div class="tablewrap">
<table>
<thead><tr><th>时间</th><th>类目</th><th>来源 IP</th><th>URI</th><th>User-Agent</th></tr></thead>
<tbody id="logrows"></tbody>
</table>
</div>
<div class="pager">
  <button id="pg-prev">上一页</button>
  <span id="pg-info" class="info">–</span>
  <button id="pg-next">下一页</button>
</div>

<footer id="foot">OpenLiteWaf</footer>

<noscript><p class="noscript">此页面需要启用 JavaScript 才能展示统计数据。</p></noscript>

<script>
var CATS={cc:"CC 频率超限",sqli:"SQL 注入",xss:"XSS",traversal:"路径穿越",rce:"命令执行",probe:"探测 / 扫描"};
var curPage=1;

function asArr(x){
  if(Array.isArray(x))return x;
  if(x&&typeof x==="object"){var a=[];for(var k in x)a.push(x[k]);return a;}
  return [];
}
function el(id){return document.getElementById(id);}
function fmtT(ts){var d=new Date(ts*1000),p=function(n){return(n<10?"0":"")+n};return p(d.getHours())+":"+p(d.getMinutes());}
function fmtDT(ts){var d=new Date(ts*1000),p=function(n){return(n<10?"0":"")+n};
  return (d.getMonth()+1)+"-"+p(d.getDate())+" "+p(d.getHours())+":"+p(d.getMinutes())+":"+p(d.getSeconds());}
function setText(id,v){el(id).textContent=v;}

function drawTrend(rows){
  rows=asArr(rows);
  var box=el("trend");
  if(rows.length===0){box.innerHTML='<div class="empty">暂无数据</div>';return;}
  var W=640,H=170,P=16,max=1;
  for(var i=0;i<rows.length;i++){if(rows[i].n>max)max=rows[i].n;}
  var bw=(W-P*2)/rows.length;
  var base=H-24,top=16;
  var s='<svg viewBox="0 0 '+W+" "+H+'" width="100%" height="170" role="img" aria-label="拦截趋势图">';
  for(var g=1;g<=3;g++){
    var gy=base-(base-top)*g/4;
    s+='<line x1="'+P+'" y1="'+gy.toFixed(1)+'" x2="'+(W-P)+'" y2="'+gy.toFixed(1)+'" stroke="#f0f2f4"/>';
  }
  s+='<line x1="'+P+'" y1="'+base+'" x2="'+(W-P)+'" y2="'+base+'" stroke="#e6e8eb"/>';
  for(var j=0;j<rows.length;j++){
    var h=Math.round(rows[j].n/max*(base-top));
    if(rows[j].n>0){
      s+='<rect x="'+(P+j*bw).toFixed(1)+'" y="'+(base-h)+'" width="'+Math.max(bw-2,2).toFixed(1)+'" height="'+h+'" rx="2" fill="#d64545" opacity="0.85">'
        +'<title>'+rows[j].n+' 次 / '+fmtT(rows[j].t)+'</title></rect>';
    }
  }
  s+='<text x="'+P+'" y="'+(H-6)+'" font-size="10" fill="#98a1ab">'+fmtT(rows[0].t)+'</text>';
  s+='<text x="'+(W-P)+'" y="'+(H-6)+'" font-size="10" fill="#98a1ab" text-anchor="end">'+fmtT(rows[rows.length-1].t)+'</text>';
  s+='<text x="'+P+'" y="10" font-size="10" fill="#98a1ab">峰值 '+max+' 次/分钟</text>';
  s+='</svg>';
  box.innerHTML=s;
}

function drawCats(blocked){
  var items=[];
  for(var k in blocked){items.push([k,blocked[k]]);}
  items.sort(function(a,b){return b[1]-a[1];});
  var max=1;
  for(var i=0;i<items.length;i++){if(items[i][1]>max)max=items[i][1];}
  var html="";
  for(var j=0;j<items.length;j++){
    var w=Math.round(items[j][1]/max*100);
    html+='<div class="barrow"><span class="lbl">'+(CATS[items[j][0]]||items[j][0])+'</span>'
      +'<span class="track"><span class="bar" style="width:'+w+'%"></span></span>'
      +'<span class="num">'+items[j][1]+'</span></div>';
  }
  el("cats").innerHTML=html||'<div class="empty">暂无数据</div>';
}

function drawTopIps(list){
  list=asArr(list);
  if(list.length===0){el("topips").innerHTML='<div class="empty">暂无攻击记录</div>';return;}
  var html="";
  for(var i=0;i<list.length;i++){
    html+='<div class="barrow"><span class="lbl mono">'+list[i].ip+'</span>'
      +'<span class="track"><span class="bar" style="width:'+Math.round(list[i].n/list[0].n*100)+'%"></span></span>'
      +'<span class="num">'+list[i].n+'</span></div>';
  }
  el("topips").innerHTML=html;
}

function fetchStats(){
  fetch("/security/stats").then(function(r){return r.json();}).then(function(j){
    setText("st-req",j.requests_total);
    setText("st-blocked",j.blocked_total);
    setText("st-ratio",j.requests_total>0?(j.blocked_total/j.requests_total*100).toFixed(1)+"%":"–");
    var m60=j.blocked_60m||0;
    setText("st-60m",m60);
    setText("st-rate",(m60/60).toFixed(1));
    setText("st-active",j.banned_active);
    el("foot").textContent="OpenLiteWaf v"+j.version+" · 运行 "+j.uptime_seconds+" 秒";
    drawTrend(j.trends);
    drawCats(j.blocked||{});
    drawTopIps(j.top_ips);
  }).catch(function(){});
}

function fetchLogs(page){
  fetch("/security/logs?page="+page).then(function(r){return r.json();}).then(function(j){
    curPage=j.page;
    var rows=asArr(j.logs),tb=el("logrows");
    tb.textContent="";
    if(rows.length===0){
      var tr=document.createElement("tr"),td=document.createElement("td");
      td.colSpan=5;td.className="empty";td.textContent="暂无攻击记录";
      tr.appendChild(td);tb.appendChild(tr);
    }else{
      for(var i=0;i<rows.length;i++){
        var e=rows[i],tr=document.createElement("tr");
        var t1=document.createElement("td");t1.className="num";t1.textContent=fmtDT(e.t);
        var t2=document.createElement("td");var tag=document.createElement("span");
        tag.className="tag";tag.textContent=CATS[e.cat]||e.cat;t2.appendChild(tag);
        var t3=document.createElement("td");t3.style.fontFamily="monospace";t3.textContent=e.ip;
        var t4=document.createElement("td");t4.textContent=e.u;
        var t5=document.createElement("td");t5.textContent=e.a;
        tr.appendChild(t1);tr.appendChild(t2);tr.appendChild(t3);tr.appendChild(t4);tr.appendChild(t5);
        tb.appendChild(tr);
      }
    }
    setText("pg-info","第 "+j.page+" / "+j.pages+" 页 · 共 "+j.total+" 条");
    el("pg-prev").disabled=j.page<=1;
    el("pg-next").disabled=j.page>=j.pages;
  }).catch(function(){});
}

el("pg-prev").addEventListener("click",function(){if(curPage>1)fetchLogs(curPage-1);});
el("pg-next").addEventListener("click",function(){fetchLogs(curPage+1);});

fetchStats();
fetchLogs(1);
setInterval(fetchStats,30000);
</script>
</body>
</html>
]==]

local function build_stats(d)
    local started = (d and d:get("c:start_epoch")) or ngx.now()
    local now = ngx.now()
    local function c(name) return (d and d:get("c:" .. name)) or 0 end

    local trends = {}
    -- 最近 60 分钟拦截数：趋势分钟桶之和（口径与趋势图一致，
    -- 不含封禁期内被拦截但无类目的请求）
    local blocked_60m = 0
    for i = CONFIG.trend_minutes - 1, 0, -1 do
        local bucket = math.floor(now / 60) - i
        local n = (d and d:get("m:" .. bucket)) or 0
        trends[#trends + 1] = { t = bucket * 60, n = n }
        blocked_60m = blocked_60m + n
    end

    return {
        name = "OpenLiteWaf",
        version = _M._VERSION,
        uptime_seconds = math.floor(now - started),
        requests_total = c("total"),
        blocked_total = c("blocked"),
        blocked_60m = blocked_60m,
        banned_active = d and count_active_bans(d) or 0,
        logs_total = d and math.min(d:get("log_seq") or 0, CONFIG.log_capacity) or 0,
        blocked = {
            cc = c("cc"),
            sqli = c("sqli"),
            xss = c("xss"),
            traversal = c("traversal"),
            rce = c("rce"),
            probe = c("probe"),
        },
        trends = trends,
        top_ips = d and top_from_logs(d) or {},
    }
end

function _M.stats()
    local d = dict()
    local uri = ngx.var.uri or CONFIG.stats_prefix

    -- JSON 输出：/security/logs（攻击日志分页）
    if uri == CONFIG.stats_prefix .. "/logs" then
        local page = tonumber(ngx.var.arg_page) or 1
        local data = (d and collect_logs(d, page)) or
            { total = 0, page = 1, pages = 1, per_page = CONFIG.log_page_size, logs = {} }
        ngx.header.content_type = "application/json; charset=utf-8"
        ngx.header["Cache-Control"] = "no-store"
        ngx.say(cjson.encode(data) or "{}")
        return
    end

    -- JSON 输出：/security/stats
    if uri == CONFIG.stats_prefix .. "/stats" then
        ngx.header.content_type = "application/json; charset=utf-8"
        ngx.header["Cache-Control"] = "no-store"
        -- cjson.safe 失败返回 nil（而非抛错），兜底空 JSON 保证端点可用
        ngx.say(cjson.encode(build_stats(d)) or "{}")
        return
    end

    -- HTML 输出：/security（骨架 + 内联 JS 渲染图表与日志）
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.say(STATS_HTML)
end

return _M
