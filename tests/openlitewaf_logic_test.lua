-- OpenLiteWaf 逻辑回归测试（Lua 5.1，stub ngx 运行真实模块代码）
-- 用法：lua5.1 OpenLiteWaf/tests/openlitewaf_logic_test.lua
-- 覆盖：白名单、CC 窗口与封禁、封禁 TTL 到期解封、特征命中与 S1 前缀绕过防护、
-- 统计页跳过语义、计数器、统计页输出、请求体检查与豁免、
-- 攻击日志写入/容量/分页、封禁槽位（活跃封禁数近似）、趋势计数。

local fail = 0
local function ok(cond, name)
    if cond then
        print("PASS  " .. name)
    else
        fail = fail + 1
        print("FAIL  " .. name)
    end
end

local LUA_PATH = debug.getinfo(1, "S").source:gsub("^@", ""):gsub("[^/]+$", "") .. "../lua/openlitewaf.lua"

-- ── 共享 dict mock（支持 TTL 惰性过期）──
local NOW = 1000000.0
local function newdict()
    local d = { store = {} }
    function d:_live(k)
        local e = self.store[k]
        if e and e.exp and NOW >= e.exp then
            self.store[k] = nil
            return nil
        end
        return e
    end
    function d:get(k)
        local e = self:_live(k)
        return e and e.v or nil
    end
    function d:set(k, v, ex)
        self.store[k] = { v = v, exp = ex and (NOW + ex) or nil }
        return true
    end
    function d:incr(k, delta, init)
        local e = self:_live(k)
        if not e then
            e = { v = init or 0, exp = nil }
            self.store[k] = e
        end
        e.v = e.v + delta
        return e.v
    end
    function d:expire(k, t)
        local e = self:_live(k)
        if e then
            e.exp = NOW + t
            return true
        end
        return false
    end
    -- ngx.shared.DICT:delete —— 解封通道清封禁键与槽位依赖它
    function d:delete(k)
        local had = self.store[k] ~= nil
        self.store[k] = nil
        return had
    end
    return d
end

-- ── ngx mock ──
-- RE_FIND 三态：nil=不命中；true=任意 subject 命中；function=按内容判定（EVIL 标记）
local RE_FIND = nil
local EXITED = nil
local SAID = nil
local REQ_METHOD = "GET"
local REQ_BODY = nil

local function hit(s)
    if not RE_FIND then return nil end
    if RE_FIND == true then return 1 end
    if type(RE_FIND) == "function" then
        if type(s) == "string" and s:find("EVIL", 1, true) then return 1 end
        return nil
    end
    return nil
end

ngx = {
    now = function() return NOW end,
    re = {
        find = function(_, s, p, f) return hit(s) end,
        -- 模拟 ngx.re.compile（预编译路径），编译行为受同一 RE_FIND 开关控制
        compile = function(_, pat, flags)
            return { find = function(_, s) return hit(s) end }, nil
        end,
    },
    unescape_uri = function(s) return s end,
    req = {
        read_body = function() end,
        get_body_data = function() return REQ_BODY end,
        get_body_file = function() return nil end,
        get_method = function() return REQ_METHOD end,
    },
    shared = { openlitewaf = newdict() },
    var = {},
    ctx = {},
    header = {},
    status = nil,
    HTTP_OK = 200,
    HTTP_NOT_FOUND = 404,
    WARN = 4,
    ERR = 1,
    NOTICE = 5,
    log = function() end,
    say = function(body) SAID = body end,
    exit = function(code) EXITED = code; error({ exit = code }) end,
}

-- cjson.safe stub：完整实现测试所需的 JSON 编解码（快照含嵌套表/数组）。
-- 编码：数字取整（与真实 cjson 数值语义兼容）、字符串转义、数组/对象递归。
-- 解码：递归下降，支持对象/数组/字符串转义/数字/布尔/null。
local function json_enc(v)
    local t = type(v)
    if v == nil then return "null" end
    if t == "boolean" then return tostring(v) end
    if t == "number" then
        if v == math.floor(v) and math.abs(v) < 2 ^ 53 then
            return string.format("%d", v)
        end
        return tostring(v)
    end
    if t == "string" then
        return '"' .. v:gsub('[%c"\\]', function(c)
            if c == '"' then return '\\"' end
            if c == "\\" then return "\\\\" end
            if c == "\n" then return "\\n" end
            if c == "\r" then return "\\r" end
            if c == "\t" then return "\\t" end
            return string.format("\\u%04x", c:byte())
        end) .. '"'
    end
    if t == "table" then
        if #v > 0 then
            local parts = {}
            for i = 1, #v do parts[i] = json_enc(v[i]) end
            return "[" .. table.concat(parts, ",") .. "]"
        end
        local parts = {}
        for k, val in pairs(v) do
            parts[#parts + 1] = json_enc(tostring(k)) .. ":" .. json_enc(val)
        end
        return "{" .. table.concat(parts, ",") .. "}"
    end
    error("cannot encode " .. t)
end

local function json_dec(s, i)
    i = i or 1
    local c = s:sub(i, i)
    while c == " " or c == "," or c == ":" or c == "\n" or c == "\r" or c == "\t" do
        i = i + 1
        c = s:sub(i, i)
    end
    if c == "{" then
        local obj = {}
        i = i + 1
        while true do
            c = s:sub(i, i)
            if c == "}" then return obj, i + 1 end
            local k
            k, i = json_dec(s, i)
            local v
            v, i = json_dec(s, i)  -- 跳过 ':' 由开头的空白/符号过滤处理
            obj[k] = v
        end
    elseif c == "[" then
        local arr = {}
        i = i + 1
        while true do
            c = s:sub(i, i)
            if c == "]" then return arr, i + 1 end
            local v
            v, i = json_dec(s, i)
            arr[#arr + 1] = v
        end
    elseif c == '"' then
        local out = {}
        i = i + 1
        while true do
            local ch = s:sub(i, i)
            if ch == "\\" then
                local n = s:sub(i + 1, i + 1)
                if n == "n" then out[#out + 1] = "\n"
                elseif n == "r" then out[#out + 1] = "\r"
                elseif n == "t" then out[#out + 1] = "\t"
                elseif n == "u" then
                    out[#out + 1] = string.char(tonumber(s:sub(i + 2, i + 5), 16) or 63)
                    i = i + 4
                else out[#out + 1] = n end
                i = i + 2
            elseif ch == '"' then
                return table.concat(out), i + 1
            else
                out[#out + 1] = ch
                i = i + 1
            end
        end
    else
        local num = s:match("^%-?%d+%.?%d*[eE]?[-+]?%d*", i)
        if num then return tonumber(num), i + #num end
        if s:sub(i, i + 3) == "true" then return true, i + 4 end
        if s:sub(i, i + 4) == "false" then return false, i + 5 end
        if s:sub(i, i + 3) == "null" then return nil, i + 4 end
        error("bad json at " .. i)
    end
end

package.loaded["cjson.safe"] = {
    encode = json_enc,
    decode = function(s) local ok, v, i = pcall(json_dec, s) if ok and i and v ~= nil then return v end return nil end,
}

local waf = dofile(LUA_PATH)

-- ── 请求模拟 ──
local function request(opts)
    ngx.var.uri = opts.uri or "/"
    ngx.var.request_uri = opts.request_uri or ngx.var.uri
    ngx.var.remote_addr = opts.ip or "1.2.3.4"
    ngx.var.http_user_agent = opts.ua or "Mozilla/5.0"
    ngx.var.http_content_length = opts.clen
    REQ_METHOD = opts.method or "GET"
    REQ_BODY = opts.body
    ngx.status = nil
    ngx.header = {}
    SAID = nil
    EXITED = nil
    RE_FIND = opts.evil and function(s) return hit(s) end or opts.hit and true or nil
    local blocked
    local okrun, err = pcall(function() waf.access() end)
    if okrun then
        blocked = false
    else
        -- ngx.exit 经 error 表抛出以模拟中断
        blocked = (type(err) == "table" and err.exit ~= nil) or false
    end
    return {
        blocked = blocked,
        status = ngx.status,
        retry = ngx.header["Retry-After"],
        banned = ngx.shared.openlitewaf:get("b:" .. (opts.ip or "1.2.3.4")) ~= nil,
        body = SAID,
        dict = ngx.shared.openlitewaf,
    }
end

-- 让某个 IP 达到封禁阈值：v1.3.0 起单次特征命中只 403，窗口内累计 sig_strikes 次才封 IP
local function ban_ip(ip, wafref)
    local strikes = (wafref or waf).CONFIG.sig_strikes
    local last
    for _ = 1, strikes do
        last = request({ uri = "/?id=1%20UNION%20SELECT%20a", hit = true, ip = ip })
    end
    return last
end

-- 干净环境（新 dict + 新模块副本），用于体检查/日志/封禁槽位等独立场景
local function fresh()
    ngx.shared.openlitewaf = newdict()
    local w = dofile(LUA_PATH)
    w.init()
    return w
end

-- 干净环境 + compile 不可用（resty.core.re 缺失的真实场景）：
-- 验证规则匹配自动回退到原生 ngx.re.find 字符串路径，拦截功能不失效
local function fresh_without_compile()
    ngx.shared.openlitewaf = newdict()
    ngx.re.compile = nil
    local w = dofile(LUA_PATH)
    w.init()
    return w
end

-- 输出 JSON 的辅助：调用 stats() 并返回 SAID
local function stats_json(w, uri, page)
    ngx.var.uri = uri
    ngx.var.request_uri = uri
    ngx.var.arg_page = page
    ngx.status = nil
    SAID = nil
    pcall(function() w.stats() end)
    return SAID
end

local function counter(d, name)
    return (d:get("c:" .. name)) or 0
end

-- T1 init 记录启动时间
waf.init()
ok(ngx.shared.openlitewaf:get("c:start_epoch") == NOW, "init 记录启动时间")

-- 惰性编译：init 阶段不持有编译结果（ngx.re.compile 在 init 阶段不可用），
-- 首次请求走 get_rules() 完成 worker 级编译；匹配行为由后续用例覆盖。
-- 经 _rules_compiled() 访问器观察真实编译缓存（此前断言访问不存在的
-- _compiled 字段恒为真，无验证能力）
ok(waf._rules_compiled() == nil, "init 阶段不做规则预编译（惰性编译在首请求）")

-- T2 白名单路径：不计数、不检查、不拦截
local r = request({ uri = "/.well-known/acme-challenge/tok123", hit = true })
ok(not r.blocked, "白名单（ACME）不拦截")
ok(counter(r.dict, "total") == 0, "白名单不计入统计")

-- T3 普通请求放行并计数
r = request({ uri = "/v1/log" })
ok(not r.blocked, "普通请求放行")
ok(counter(r.dict, "total") == 1, "普通请求计入 total")
ok(waf._rules_compiled() ~= nil, "首个非豁免请求触发规则惰性编译并缓存")

-- T4 统计页：跳过特征匹配（即使规则命中）但计入 total
r = request({ uri = "/security", hit = true })
ok(not r.blocked, "统计页跳过特征匹配")

-- T5 CC：第 limit+1 次触发节流（窗口内），返回 429 且不封 IP
local d
for i = 1, 241 do
    d = request({ uri = "/v1/log", ip = "5.6.7.8" })
end
ok(d.blocked and d.status == 429, "CC 超限返回 429")
ok(d.retry ~= nil, "CC 响应带 Retry-After")
ok(d.body and d.body:find("频率过高", 1, true) ~= nil, "CC 拦截返回警告页")
ok(counter(d.dict, "cc") == 1, "CC 触发计入 cc 计数")
ok(not d.banned, "CC 不写封禁名单（对 CGNAT 出口不该整片封）")

-- T6 CC 只节流不封禁：同一窗口内继续 429，跨窗口自动恢复
r = request({ uri = "/v1/log", ip = "5.6.7.8" })
ok(r.blocked and r.status == 429, "同一窗口内持续 429")
NOW = NOW + 11
r = request({ uri = "/v1/log", ip = "5.6.7.8" })
ok(not r.blocked, "新窗口内 CC 自动恢复")

-- T7 窗口滑动：新窗口恢复计数（换未封禁 IP）
NOW = NOW + 11
r = request({ uri = "/v1/log", ip = "9.9.9.9" })
ok(not r.blocked, "新窗口内正常放行")

-- T8 特征命中：单次只 403，不封 IP
NOW = NOW + 1
r = request({ uri = "/?id=1%20UNION%20SELECT%20a", ip = "7.7.7.7", hit = true })
ok(r.blocked and r.status == 403, "特征命中返回 403")
ok(counter(r.dict, "sqli") == 1, "特征命中计入类目")
ok(not r.banned, "单次命中不封 IP（未达 sig_strikes 阈值）")

-- T9 窗口内累计达阈值才封禁；封禁期内即使不命中特征也拦截
NOW = NOW + 1
request({ uri = "/?id=1%20UNION%20SELECT%20a", ip = "7.7.7.7", hit = true })
r = request({ uri = "/?id=1%20UNION%20SELECT%20a", ip = "7.7.7.7", hit = true })
ok(r.banned, "累计三次命中后封禁 IP")
NOW = NOW + 1
r = request({ uri = "/v1/log", ip = "7.7.7.7", hit = false })
ok(r.blocked and r.status == 403, "特征封禁期内持续拦截")

-- T10 其它 IP 不受影响
r = request({ uri = "/v1/log", ip = "8.8.8.8" })
ok(not r.blocked, "封禁不影响其他 IP")

-- T11 统计页 JSON
local js = stats_json(waf, "/security/stats")
ok(js and js:find('"blocked_total"', 1, true) ~= nil, "JSON 统计页输出成功")
ok(js and js:find('"blocked_total"', 1, true) ~= nil and js:find('"trends"', 1, true) ~= nil
    and js:find('"banned_active"', 1, true) ~= nil and js:find('"top_ips"', 1, true) ~= nil
    and js:find('"blocked_60m"', 1, true) ~= nil,
    "JSON 含新增字段（trends/banned_active/top_ips/blocked_60m）")
ok(js and js:find('"banned_total"', 1, true) == nil, "JSON 不再输出累计封禁次数")

-- T12 统计页 HTML
js = stats_json(waf, "/security")
ok(js and js:find("OpenLiteWaf 安全统计", 1, true) ~= nil, "HTML 统计页输出成功")
ok(js and js:find("/security/logs", 1, true) ~= nil, "HTML 含日志分页脚本引用")

-- T13 S1 回归：/security 前缀变体必须走特征检查，不得绕过
r = request({ uri = "/securityXYZ", hit = true, ip = "11.1.1.1" })
ok(r.blocked, "/security 前缀变体不可绕过特征检查")
r = request({ uri = "/security/evil", hit = true, ip = "11.1.1.2" })
ok(r.blocked, "/security/ 子路径不可绕过特征检查")

-- T14 统计页三个精确 URI 仍跳过特征匹配
r = request({ uri = "/security", hit = true, ip = "12.1.1.1" })
ok(not r.blocked, "/security 精确匹配跳过特征")
r = request({ uri = "/security/stats", hit = true, ip = "12.1.1.2" })
ok(not r.blocked, "/security/stats 精确匹配跳过特征")
r = request({ uri = "/security/logs", hit = true, ip = "12.1.1.3" })
ok(not r.blocked, "/security/logs 精确匹配跳过特征")

-- T15 封禁 TTL 到期自动解封（特征封禁，sig_ban=600）
local banip = "13.1.1.1"
r = ban_ip(banip)
ok(r.banned, "T15 累计命中触发封禁")
NOW = NOW + 601
r = request({ uri = "/v1/log", ip = banip })
ok(not r.blocked, "封禁到期后自动解封")

-- ═══════ 以下为独立干净环境场景（新 dict + 新模块）═══════

-- T16 请求体检查：body 命中特征拦截（URI/UA 正常，仅 body 含 EVIL）
do
    local w = fresh()
    local before = NOW
    r = request({
        uri = "/api/submit", method = "POST", clen = "48",
        body = 'EVIL {"q":"<script>alert(1)</script>"}', evil = true, ip = "14.1.1.1",
    })
    ok(r.blocked and r.status == 403, "body 命中特征返回 403")
    ok(counter(ngx.shared.openlitewaf, "sqli") == 1, "body 命中计入类目")
    js = stats_json(w, "/security/logs", "1")
    ok(js and js:find('"total":1', 1, true) ~= nil, "body 命中写入攻击日志")
    ok(NOW == before, "体检查不推进时钟")
end

-- T17 body 豁免：日志内容与分析端点不查 body
do
    fresh()
    r = request({
        uri = "/v1/log", method = "POST", clen = "48",
        body = 'EVIL {"q":"<script>alert(1)</script>"}', evil = true, ip = "14.2.1.1",
    })
    ok(not r.blocked, "日志端点 body 豁免（业务误报防护）")
    ok(counter(ngx.shared.openlitewaf, "total") == 1, "豁免请求仍计入 total")

    -- S1 回归：/v1/ai/analyse 端点直传含 SQL 错误栈的日志不被拦截
    r = request({
        uri = "/v1/ai/analyse", method = "POST", clen = "60",
        body = '{"content":"SELECT * FROM users WHERE id=1; fail"}', evil = true, ip = "14.2.1.2",
    })
    ok(not r.blocked, "AI 分析端点 body 豁免（S1 回归）")

    -- S2 回归：/v1/raw/abc/latest.log 正常放行，不命中 probe 扩展名规则
    r = request({
        uri = "/v1/raw/s123456/latest.log", method = "GET",
        ip = "14.2.1.3",
    })
    ok(not r.blocked, "合法 raw 附件下载放行（S2 回归）")

    -- S2 防御：raw 路径若包含恶意特征仍被拦截
    r = request({
        uri = "/v1/raw/s123456/../../etc/passwd", method = "GET",
        hit = true, ip = "14.2.1.4",
    })
    ok(r.blocked, "raw 路径上的恶意特征仍被拦截（S2 防御）")

    -- v1.3.0：前端遥测与管理端同样属"任意用户文本摄入"，body 不查特征
    r = request({
        uri = "/v1/telemetry/report", method = "POST", clen = "80",
        body = 'EVIL {"items":[{"endpoint":"https://logshare.cn/v1/raw/qKSA1QU/main.log"}]}',
        evil = true, ip = "14.2.1.5",
    })
    ok(not r.blocked, "遥测端点 body 豁免（本次线上误封回归）")

    r = request({
        uri = "/v1/admin/rag/docs/save", method = "POST", clen = "60",
        body = 'EVIL {"content":"# 排障\\n执行 `whoami` 或 curl https://example.com 并读 ../config.yml"}',
        evil = true, ip = "14.2.1.6",
    })
    ok(not r.blocked, "管理端 body 豁免（知识库正文含反引号与 curl）")

    -- 豁免只作用于 body：这些端点 URI/UA 上的攻击特征仍拦
    r = request({ uri = "/v1/telemetry/report?x=EVIL", evil = true, ip = "14.2.1.7" })
    ok(r.blocked, "body 豁免不影响 URI 检查")
    r = request({ uri = "/v1/admin/logs", ua = "EVIL/1.0", evil = true, ip = "14.2.1.8" })
    ok(r.blocked, "body 豁免不影响 UA 检查")
end

-- T18 body 尺寸超限跳过检查
do
    fresh()
    r = request({
        uri = "/api/submit", method = "POST", clen = "99999999",
        body = "EVIL", evil = true, ip = "14.3.1.1",
    })
    ok(not r.blocked, "Content-Length 超限的 body 跳过扫描")
end

-- T19 攻击日志写入：脱敏 + 字段完整
do
    local w = fresh()
    r = request({
        uri = "/?id=1&token=secret123&x=1", ua = "EVIL/1.0 scanner",
        hit = true, ip = "192.168.55.77",
    })
    js = stats_json(w, "/security/logs", "1")
    ok(js and js:find("secret123", 1, true) == nil, "日志 URI 中 token 原值不泄露")
    ok(js and js:find("token=***", 1, true) ~= nil, "日志 URI 中 token 参数已打码")
    ok(js and js:find("192.168.55.77", 1, true) == nil
        and js:find("192.168.*.*", 1, true) ~= nil, "日志 IP 已脱敏")
    ok(js and js:find('"cat"', 1, true) ~= nil and js:find('"t"', 1, true) ~= nil,
        "日志条目含类目与时间字段")
    ok(js and js:find('"rule"', 1, true) ~= nil and js:find('"via":"uri"', 1, true) ~= nil,
        "日志条目含命中规则序号与匹配对象")
end

-- T19b 命中对象与规则序号可归因；请求体内容绝不进日志与公开页
do
    local w = fresh()
    request({
        uri = "/api/submit", method = "POST", clen = "60",
        body = 'EVIL {"secret":"TOP-SECRET-BODY"}', evil = true, ip = "19.9.9.9",
    })
    js = stats_json(w, "/security/logs", "1")
    ok(js and js:find('"via":"body"', 1, true) ~= nil, "body 命中记为 via=body")
    ok(js and js:find("TOP-SECRET-BODY", 1, true) == nil, "请求体内容不写入攻击日志")
    ok(js and js:find("EVIL", 1, true) == nil, "命中片段不写入攻击日志")
end

-- T20 日志容量 500 与分页（每页 50）
do
    local w = fresh()
    -- 写 520 条：每个 IP 少量请求，避免触发 CC
    for i = 1, 520 do
        request({
            uri = "/?p=" .. i, hit = true,
            ip = "20." .. math.floor(i / 200) .. "." .. (i % 200) .. ".1",
        })
    end
    js = stats_json(w, "/security/logs", "1")
    ok(js and js:find('"total":500', 1, true) ~= nil, "日志容量封顶 500 条")
    ok(js and js:find('"pages":10', 1, true) ~= nil, "分页数按 500/50 计算")
    local n1 = select(2, js:gsub('"cat"', ""))
    ok(n1 == 50, "第 1 页 50 条")
    js = stats_json(w, "/security/logs", "10")
    local n10 = select(2, js:gsub('"cat"', ""))
    ok(n10 == 50, "第 10 页 50 条")
    js = stats_json(w, "/security/logs", "11")
    ok(js and js:find('"page":10', 1, true) ~= nil, "越界页码收敛到最后一页")
    js = stats_json(w, "/security/logs", "0")
    ok(js and js:find('"page":1', 1, true) ~= nil, "非法页码收敛到第 1 页")
end

-- T21 封禁槽位：活跃封禁数近似与到期衰减
do
    local w = fresh()
    -- 特征封禁 1 个 IP（累计到 sig_strikes 才封）
    ban_ip("15.1.1.1")
    js = stats_json(w, "/security/stats")
    ok(js and js:find('"banned_active":1', 1, true) ~= nil, "活跃封禁数为 1")
    ok(js and js:find('"banned_total"', 1, true) == nil, "封禁发生不产生累计封禁次数指标")
    ok(js and js:find('"ban_reasons"', 1, true) ~= nil
        and js:find('"sqli#', 1, true) ~= nil, "stats 输出封禁原因分布（类目#规则序号）")
    -- 再封 2 个
    ban_ip("15.1.1.2")
    ban_ip("15.1.1.3")
    js = stats_json(w, "/security/stats")
    ok(js and js:find('"banned_active":3', 1, true) ~= nil, "活跃封禁数累计到 3")
    -- 封禁到期（sig_ban=600）后槽位衰减
    NOW = NOW + 601
    js = stats_json(w, "/security/stats")
    ok(js and js:find('"banned_active":0', 1, true) ~= nil, "封禁到期后活跃数归零")
end

-- T22 趋势计数：分钟桶写入与 stats 趋势数组
do
    local w = fresh()
    request({ uri = "/?id=1 UNION", hit = true, ip = "16.1.1.1" })
    ok(ngx.shared.openlitewaf:get("m:" .. math.floor(NOW / 60)) == 1, "分钟桶计数写入")
    js = stats_json(w, "/security/stats")
    ok(js and js:find('"trends"', 1, true) ~= nil, "stats 含趋势数组")
    ok(js and js:find('"blocked_60m":1', 1, true) ~= nil, "最近 60 分钟拦截数等于分钟桶之和")
end

-- T23 top_ips 聚合（注意：同 IP 首次攻击即被封禁，后续请求不再产生攻击日志，
-- 故用同前缀的不同 IP 验证脱敏桶聚合）
do
    local w = fresh()
    request({ uri = "/?id=1 UNION", hit = true, ip = "17.1.1.9" })
    request({ uri = "/?id=1 UNION", hit = true, ip = "17.1.1.8" })
    request({ uri = "/?id=1 UNION", hit = true, ip = "17.1.1.7" })
    request({ uri = "/?id=1 UNION", hit = true, ip = "18.1.1.6" })
    js = stats_json(w, "/security/stats")
    ok(js and js:find('"top_ips"', 1, true) ~= nil, "stats 含 top_ips")
    ok(js and js:find('"n":3', 1, true) ~= nil, "同前缀 IP 脱敏后聚合计数正确")
end

-- T24 compile 不可用（resty.core.re 缺失，线上真实事故场景）：
-- get_rules 必须回退字符串路径，拦截功能完整可用
do
    local w = fresh_without_compile()
    local r = request({ uri = "/?id=1 UNION", hit = true, ip = "19.1.1.1" })
    ok(r.blocked and r.status == 403, "compile 不可用时回退字符串路径仍拦截")
    ok(w._rules_compiled() == nil, "回退路径不产生编译缓存（直接使用原始规则表）")
    -- 恢复 compile 供后续用例使用
    ngx.re.compile = function(_, flags)
        return { find = function(_, s) return hit(s) end }, nil
    end
end

-- T25 快照持久化：计数 / 攻击日志 / 封禁名单的保存与恢复（真实文件 IO，临时目录）
do
    local dir = "/data/data/com.termux/files/usr/tmp/wafdbg/snaptest"
    os.execute("mkdir -p " .. dir)
    os.remove(dir .. "/snapshot.json")
    local w1 = fresh()
    w1.CONFIG.data_dir = dir
    ban_ip("30.1.1.1")
    local seq_before = ngx.shared.openlitewaf:get("log_seq")
    ok(w1._save(ngx.shared.openlitewaf) == true, "T25 快照写入成功")
    -- 新 dict + 新模块：模拟进程重启后的 init 恢复
    ngx.shared.openlitewaf = newdict()
    local w2 = dofile(LUA_PATH)
    w2.CONFIG.data_dir = dir
    w2.init()
    local d2 = ngx.shared.openlitewaf
    ok(counter(d2, "total") == 3, "T25 计数器恢复（三次命中）")
    ok(counter(d2, "sqli") == 3, "T25 类目计数恢复")
    ok(d2:get("b:30.1.1.1") ~= nil, "T25 封禁名单恢复")
    ok(d2:get("bx:0") == "sqli#1", "T25 封禁原因随快照恢复")
    ok(d2:get("log_seq") == seq_before, "T25 攻击日志序列恢复")
    -- 恢复后的封禁仍然生效（封禁期内拦截、不重复计类目）
    local r25 = request({ uri = "/v1/log", ip = "30.1.1.1" })
    ok(r25.blocked, "T25 恢复的封禁仍拦截")
    ok(counter(d2, "sqli") == 3, "T25 恢复后封禁期不重复计类目")
    os.remove(dir .. "/snapshot.json")
end

-- T26 IPv6 脱敏与压缩展开
do
    local w = fresh()
    ok(w._mask_ip("::1") == "0:0:0::*", "T26 IPv6 回环 ::1 展开脱敏")
    ok(w._mask_ip("fe80::1") == "fe80:0:0::*", "T26 IPv6 压缩 fe80::1 展开脱敏")
    ok(w._mask_ip("2001:db8::1") == "2001:db8:0::*", "T26 IPv6 压缩 2001:db8::1 展开脱敏")
    ok(w._mask_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:0db8:85a3::*", "T26 IPv6 完整地址脱敏")
end

-- T27 规则作用域掩码：路径形态的探测特征不得参与 body/UA 匹配
do
    local w = fresh()   -- 必须在任何请求之前取掩码（掩码按模块实例惰性构建）
    local ALL, PATH, UA, URI, BODY = 15, 2, 4, 1, 8
    local function idx_of(needle)
        for i, rule in ipairs(w.RULES) do
            if type(rule[2]) == "string" and rule[2]:find(needle, 1, true) then return i end
        end
        return 0
    end
    -- 先塞一条作用域拼错的规则，再一次性构建掩码表（覆盖"退化全对象"分支）
    w.RULES[#w.RULES + 1] = { "sqli", [[zzz]], "bogus" }
    local bogus = #w.RULES

    local ext = idx_of([[\.(sql|bak]])
    ok(ext > 0, "可定位敏感文件扩展名规则")
    ok(w._rule_scope_mask(ext) == PATH, "扩展名探测规则只作用于请求路径（不含 query）")
    ok(w._rule_scope_mask(idx_of([[union\s+]])) == ALL, "未声明作用域的规则仍作用于全部匹配对象")
    ok(w._rule_scope_mask(idx_of([[sqlmap|nikto]])) == UA + URI, "扫描器 UA 规则作用于 UA 与 URI，不扫 body")
    local fname = idx_of([[filename=]])
    ok(fname > 0 and w._rule_scope_mask(fname) == BODY, "上传文件名规则只作用于请求体")
    ok(w._rule_scope_mask(idx_of([[/(\.env|\.git]])) == URI, "dotfile 探测规则只作用于 URI 侧，不扫 body/UA")
    ok(w._rule_scope_mask(bogus) == ALL, "非法作用域退化为全对象")
end

-- T28 运维端点：令牌鉴权、解封清槽与立即落盘、被误封者可用
do
    local dir = "/data/data/com.termux/files/usr/tmp/wafdbg/adm"
    os.execute("mkdir -p " .. dir)
    os.remove(dir .. "/snapshot.json")
    local w = fresh()
    w.CONFIG.data_dir = dir

    local function admin_call(opts)
        ngx.var.uri = opts.uri or "/security/unban"
        ngx.var.request_uri = ngx.var.uri
        ngx.var.remote_addr = opts.ip or "127.0.0.1"
        ngx.var.http_user_agent = "curl/8.5.0"
        ngx.var.http_x_openlitewaf_token = opts.token
        ngx.var.arg_ip = opts.ip_param
        ngx.status = nil
        SAID = nil
        EXITED = nil
        local okrun = pcall(function() w.admin() end)
        return { said = SAID, exit = EXITED, status = ngx.status, ran = okrun }
    end

    w.CONFIG.admin_token = ""
    local a = admin_call({ token = "0123456789abcdef", ip_param = "1.2.3.4" })
    ok(a.exit == 404 and a.said == nil, "未配置令牌时端点 404（fail-closed）")
    w.CONFIG.admin_token = "0123456789abcdef"
    a = admin_call({ token = "0123456789abcde", ip_param = "1.2.3.4" })
    ok(a.exit == 404, "令牌不匹配时 404，不区分不存在与无权限")

    -- 先造一次真实封禁，再解封
    w.CONFIG.admin_token = nil
    local victim = "31.1.1.1"
    ban_ip(victim)
    local d = ngx.shared.openlitewaf
    ok(d:get("b:" .. victim) ~= nil, "解封前该 IP 处于封禁状态")
    w.CONFIG.admin_token = "0123456789abcdef"
    a = admin_call({ token = "0123456789abcdef", ip_param = victim })
    ok(a.said and a.said:find('"ok":true', 1, true) ~= nil, "解封调用成功")
    ok(d:get("b:" .. victim) == nil, "解封删除封禁名单键")
    ok(d:get("s:" .. victim) == nil, "解封同时清零 strike 计数")
    ok(d:get("br:0") == nil and d:get("bs:0") == nil and d:get("bx:0") == nil,
        "解封清理封禁槽位（否则快照会在 60 秒内把它写回）")
    local f = io.open(dir .. "/snapshot.json", "rb")
    local snap = f and f:read("*a") or ""
    if f then f:close() end
    ok(snap ~= "" and snap:find(victim, 1, true) == nil, "解封后立即落盘，restart 不再复活封禁")

    -- /security/bans 列出现封禁及其原因（运维排查入口）
    ban_ip("33.1.1.1")
    a = admin_call({ uri = "/security/bans", token = "0123456789abcdef" })
    ok(a.said and a.said:find("33.1.1.1", 1, true) ~= nil
        and a.said:find("sqli#1", 1, true) ~= nil, "/security/bans 输出封禁 IP 与封禁原因")

    -- 非法 ip 参数：拒且不动任何键（拼错的值会变成 shared dict 的任意键名）
    d:set("b:9.9.9.9", 1, 600)
    a = admin_call({ token = "0123456789abcdef", ip_param = "total" })
    ok(a.status == 400 and a.said:find('"ok":false', 1, true) ~= nil, "非 IP 字面量的 ip 参数返回 400")
    a = admin_call({ token = "0123456789abcdef", ip_param = "9.9.9.9;del" })
    ok(a.status == 400, "带分隔符注入的 ip 参数被拒")
    ok(d:get("b:9.9.9.9") ~= nil, "被拒的调用不动任何封禁键")

    -- 被误封的管理者仍能访问运维端点自身；前缀变体不能绕过封禁检查
    local adminip = "32.1.1.1"
    ban_ip(adminip)
    r = request({ uri = "/v1/log", ip = adminip })
    ok(r.blocked, "封禁期内普通端点仍被拦")
    r = request({ uri = "/security/unban", ip = adminip })
    ok(not r.blocked, "封禁期内可访问 /security/unban 自助解封")
    r = request({ uri = "/security/unbanish", ip = adminip, hit = true })
    ok(r.blocked, "/security/unban 前缀变体不得绕过封禁名单检查")
    r = request({ uri = "/security/unban", ip = adminip, hit = true })
    ok(not r.blocked, "运维端点自身跳过特征匹配（精确 URI）")
    os.remove(dir .. "/snapshot.json")
end

-- T29 旧格式快照（无封禁原因字段）必须能恢复且不报错
do
    local dir = "/data/data/com.termux/files/usr/tmp/wafdbg/oldsnap"
    os.execute("mkdir -p " .. dir)
    local f = io.open(dir .. "/snapshot.json", "wb")
    if f then
        f:write('{"version":"1.2.0","counters":{"total":7,"sqli":2},'
            .. '"bans":[{"slot":3,"exp":' .. tostring(NOW + 500) .. ',"ip":"40.1.1.1"}],'
            .. '"trends":[],"logs":[],"ban_seq":4,"log_seq":2}')
        f:close()
    end
    ngx.shared.openlitewaf = newdict()
    local w = dofile(LUA_PATH)
    w.CONFIG.data_dir = dir
    w.init()
    local d = ngx.shared.openlitewaf
    ok(d:get("b:40.1.1.1") ~= nil, "旧快照的封禁仍能恢复")
    ok(counter(d, "total") == 7, "旧快照的计数仍能恢复")
    js = stats_json(w, "/security/stats")
    ok(js and js:find('"banned_active":1', 1, true) ~= nil, "旧快照恢复后活跃封禁数正确")
    ok(js and js:find('"?"', 1, true) ~= nil, "缺原因的历史封禁归入 ? 而不报错")
    os.remove(dir .. "/snapshot.json")
end

print(fail == 0 and "全部通过" or (fail .. " 项失败"))
os.exit(fail == 0 and 0 or 1)
