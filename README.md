# OpenLiteWaf

运行在 nginx 容器内的 OpenResty Lua WAF。在反向代理层对请求做 CC 限速与攻击特征检查，并维护一个公开的统计页。它工作在 nginx access 阶段，所有状态保存在 `lua_shared_dict` 中，并定时快照到挂载目录实现持久化（进程重启自动恢复，最多丢失最近一个快照间隔的数据；目录不可写时退化为内存模式）。许可证：MIT。

代码结构：

```
OpenLiteWaf/
├── lua/
│   ├── openlitewaf.lua   # 核心模块：配置、规则、检查逻辑、统计与运维输出
│   ├── waf.lua           # access_by_lua_file 入口，调用 openlitewaf.access()
│   ├── stats.lua         # content_by_lua_file 入口，调用 openlitewaf.stats()
│   └── admin.lua         # content_by_lua_file 入口，调用 openlitewaf.admin()（需令牌）
├── nginx/nginx.conf      # OpenResty 主配置（env 透传、lua_package_path、shared dict、init）
└── tests/                # 回归测试，见"规则维护"
```

## 工作方式

每个请求进入 access 阶段后按固定顺序检查，任一步命中即终止。ACME 白名单路径（`/.well-known/acme-challenge/`）直接放行；已在封禁名单中的 IP 返回 403，但运维端点两个精确 URI（`/security/unban`、`/security/bans`）例外——否则被误封的管理者无法自助解封（它们仍计入请求数、仍受 CC 约束）；CC 计数超过窗口阈值时返回 429 并带 `Retry-After`，不写封禁名单；统计页与运维端点的五个精确 URI（`/security`、`/security/stats`、`/security/logs`、`/security/unban`、`/security/bans`）跳过特征检查；其余请求进入特征匹配。任何前缀变体（`/securityXYZ`、`/security/unbanish`）都不在豁免之内。

特征匹配的对象依次为：原始 `request_uri`（保留编码形态，用于捕获 `%2e%2e%2f` 一类编码特征）、规范化路径、`User-Agent`、完整 URL 解码后的 `request_uri`（含 query）、请求体、请求体的一次 URL 解码。URL 解码只做一层：两层编码能被解码后的检查对象覆盖，三层编码则绕过。规则表按定义顺序匹配，命中即停，命中的类目决定计数归属与警告页显示的类目。

并非每条规则都作用于全部匹配对象：规则可选的第三元素声明它自己的作用域（`uri` / `path` / `ua` / `body`，空格分隔，省略即全部）。路径形态的探测特征（`.php`、`/.git/`、`/cgi-bin/`、敏感文件扩展名等）只标 `uri` 或 `path`——请求体与 `User-Agent` 里出现 `main.log`、`phpmyadmin`、`config.yml` 只是文本内容（日志分享、知识库文档、前端遥测），把它们判为探测会封掉正常客户端的 IP。注入、跨站、穿越、命令执行等特征仍作用于全部对象，包括请求体。作用域写错（拼出未知词）时该条规则退化为全对象并在 error log 告警：宁可多扫，绝不静默关掉一条规则。

请求体检查只对 POST/PUT/PATCH 生效，且要求 `Content-Length` 不超过 2MB，扫描范围为前 64KB——body 超出 nginx `client_body_buffer_size` 落盘时读文件头部。payload 置于 64KB 之后或拆入超限请求可以绕过，这是内存与 IO 成本上的取舍。日志内容、遥测与管理端类端点（见 `body_exempt_prefixes`：`/v1|/1/log`、`/v1|/1/ai/analyse`、`/v1|/1/analyse`、`/v1|/1/telemetry`、`/v1|/1/admin`）整体豁免 body 检查：这些端点接收的是任意用户文本，其中出现攻击特征属于正常业务，做扫描只会误封；豁免只跳过 body，URI 与 UA 上的攻击特征仍被拦。若新增接收任意文本的端点，应将其加入该列表。

命中特征后，该次请求返回 403，并在窗口（`sig_strike_window`）内为该 IP 累计一次命中；累计达到 `sig_strikes` 次才真正封禁 IP（默认 600 秒）。封禁的意义是压制复读型扫描器，而单次误判的代价从「该 IP 全站 403 十分钟」降为「一次 403」。命中与封禁都会按类目计数、写攻击日志与分钟趋势（封禁期内被拒的请求只计 `blocked`，不重复计类目）。警告页为卡片组件（无页面外壳，支持 iframe 嵌入）；命中的规则序号与匹配对象写入公开日志与 error log，命中片段本身绝不记录，请求体内容不会出现在任何页面上。

## 统计页

`GET /security` 返回 HTML 页面，由内联 JS 渲染并每 30 秒轮询刷新，需要浏览器启用 JavaScript。数据接口有两个 JSON 端点：

`GET /security/stats` 返回汇总：累计请求与拦截数（`requests_total`、`blocked_total`）、最近 60 分钟拦截数（`blocked_60m`，为 `trends` 各分钟桶之和，不含封禁期内无类目的拦截）、按类目分布（`blocked`，含 `cc`、`sqli`、`xss`、`traversal`、`rce`、`probe`）、当前封禁 IP 数（`banned_active`）、封禁原因分布（`ban_reasons`，键形如 `probe#57` / `cc`，`?` 表示由旧版快照恢复、当时还没有原因记录）、缓存日志条数（`logs_total`）、最近 60 分钟逐分钟拦截数（`trends`）与来源 IP Top（`top_ips`，按最近日志聚合）。

`blocked_total` 统计每一次被拒的请求（含封禁期内重复拦截），各类目之和只计有类目的判定，两者之差即封禁期重复拦截数，判读误封时不要混用。`GET /stats/data` 一侧同理：被本模块拒绝的请求由 `ngx.ctx.olw_blocked` 标记，不进入 OpenLiteStats 的访问统计。

`GET /security/logs?page=N` 返回攻击日志分页，每页 50 条，最新在前，页码越界时收敛到边界页。每条记录包含时间（`t`）、类目（`cat`）、命中规则序号与匹配对象（`rule`、`via`，取值 `uri` 原始请求串 / `path` 请求路径 / `ua` 客户端标识 / `body` 请求体）、脱敏 IP（`ip`）、URI（`u`）与 User-Agent（`a`）。

公开页面的隐私处理：IP 一律脱敏（IPv4 保留前两段，IPv6 保留前三组），URI 中的 `token=` 参数值替换为 `***`，完整 IP 只出现在 nginx error log 的拦截记录中。统计页是公开端点，攻击者同样可以访问，它受 CC 限流保护。

数据以环形槽位保存在 shared dict：攻击日志 500 条、封禁槽位 1024 个，写满后覆盖最旧记录。shared dict 不支持枚举键，`banned_active` 通过遍历封禁槽位统计未到期数量得出，同一 IP 重复封禁会覆盖槽位，结果可能低估。

持久化：worker 0 每 60 秒将计数、趋势分钟桶、攻击日志环形缓冲与未到期封禁名单（封禁 IP 登记环 `br:*` 连同原因环 `bx:*`）写为 `/data/openlitewaf/snapshot.json`（临时文件 + rename 原子替换），`init_by_lua` 阶段恢复；封禁按剩余 TTL 重建。旧版快照没有 `why` 字段，恢复后原因记为 `?`。快照间隔内的数据变更在进程崩溃时丢失。`/data/openlitewaf` 须以读写挂载（nginx 侧），目录不可写时退化为内存模式；应用容器一侧保持只读挂载即可，解封走 HTTP 而非改文件。

## 部署

nginx 服务使用 OpenResty 镜像（当前适配 `openresty/openresty:1.27.1.2-alpine`），相关挂载：

```yaml
volumes:
  - ./nginx:/etc/nginx/conf.d:ro                                    # 站点配置
  - ../OpenLiteWaf/nginx/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro
  - ../OpenLiteWaf/lua:/usr/local/openresty/nginx/lua:ro
  - ../OpenLiteWaf/data:/data/openlitewaf                           # 快照持久化目录（读写）
```

站点配置的 80 与 443 两个 server 都需要 `access_by_lua_file`，443 另有统计与运维 location（运维端点只挂 443，避免令牌经明文信道传输；`/security/unban` 只接受 POST）：

```nginx
access_by_lua_file /usr/local/openresty/nginx/lua/waf.lua;
location = /security       { content_by_lua_file /usr/local/openresty/nginx/lua/stats.lua; }
location = /security/stats { content_by_lua_file /usr/local/openresty/nginx/lua/stats.lua; }
location = /security/logs  { content_by_lua_file /usr/local/openresty/nginx/lua/stats.lua; }
location = /security/unban { content_by_lua_file /usr/local/openresty/nginx/lua/admin.lua; }
location = /security/bans  { content_by_lua_file /usr/local/openresty/nginx/lua/admin.lua; }
```

`env OPENLITEWAF_ADMIN_TOKEN;`（主配置 http 段之外的主配置级，见 `nginx/nginx.conf`）是解封端点读到令牌的前提：nginx 默认不把环境变量交给 Lua，缺这条指令时 `os.getenv` 取不到值，端点一律 404。

独立部署时需在 http 级提供 `lua_package_path`、`lua_shared_dict openlitewaf 16m` 与 `init_by_lua_block`（见 `nginx/nginx.conf`），再挂接上述 location。

改动 Lua 文件后需要让 OpenResty 重新读取：容器化部署用 `docker restart <nginx 容器>`；`nginx -s reload` 在挂载了快照数据目录的部署里不可靠（容器内 pid 文件可能指向已失效的 master，HUP 送不达），且 `b:*` 封禁键在 reload 中保留、重启又会从快照恢复，重载本身不是解封手段。OpenResty 默认开启 `lua_code_cache`，`git pull` 只更新磁盘文件，不重载则 worker 仍运行旧代码。

升级 OpenResty 镜像 tag 时，核对 `nginx/nginx.conf` 与镜像内置配置的差异（lua 指令、临时路径、默认 include），必要时重新挂载。

## 运维端点

封禁是 IP 级、跨端点、且随快照持久化的：一次误判会让该来源在 `sig_ban` 秒内对所有路径返回 403，而 `docker restart` 并不会清掉它（`init_by_lua` 会从 `snapshot.json` 的封禁名单恢复）。因此模块提供两个特权端点，令牌取自 `OPENLITEWAF_ADMIN_TOKEN`，走 `X-OpenLiteWaf-Token` 请求头（不走 query，避免令牌落进 access_log）：

```bash
curl -sk -H "X-OpenLiteWaf-Token: $TOKEN" "https://<host>/security/bans"
curl -sk -X POST -H "X-OpenLiteWaf-Token: $TOKEN" "https://<host>/security/unban?ip=1.2.3.4"
```

`/security/bans` 列出现存封禁槽位（IP、剩余 TTL、封禁原因）；`/security/unban` 删除该 IP 的封禁键、命中计数（strike）、CC 窗口计数与全部封禁槽位，并立即重写快照——只删封禁键不清槽位的话，worker 0 的定时快照会在 60 秒内把它写回，重启时又会复活。`ip` 参数只接受 IP 字面量（字符集与长度受限），拼错的值不会变成 shared dict 的任意键名。

未配置或令牌长度不足 16 字符时，两个端点一律返回 404（fail-closed，不区分「不存在」与「无权限」）；令牌比对使用不短路的逐字节比较。此时唯一的即时解封手段是停服改文件：`docker compose stop nginx` → 从 `OpenLiteWaf/data/snapshot.json` 的 `bans[]` 里删掉该 IP 的槽位 → `docker compose start nginx`（否则最长等 `sig_ban` 秒自然到期）。

## 配置

全部配置集中在 `lua/openlitewaf.lua` 顶部的 `CONFIG` 表：

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `cc.window` / `cc.limit` | 10 / 240 | CC 窗口秒数 / 窗口内请求上限（超限返回 429，不封禁） |
| `sig_ban` | 600 | 达到封禁阈值后的封禁秒数 |
| `sig_strikes` / `sig_strike_window` | 3 / 600 | 窗口内累计命中多少次攻击特征才封禁 IP（`1` = 命中即封，退回旧行为） |
| `whitelist_prefixes` | `/.well-known/acme-challenge/` | 完全白名单，不计数不检查 |
| `admin_token_env` | `OPENLITEWAF_ADMIN_TOKEN` | 运维端点令牌所在的环境变量名（需 nginx 主配置 `env` 指令透传） |
| `body_exempt_prefixes` | 见上节 | 请求体检查豁免前缀（日志、分析、遥测、管理端） |
| `body_scan_limit` / `body_size_limit` | 65536 / 2MB | body 扫描前 N 字节 / 超过该 Content-Length 跳过 |
| `log_capacity` / `log_page_size` | 500 / 50 | 攻击日志环形容量 / 每页条数 |
| `ban_slots` | 1024 | 封禁槽位数 |
| `trend_minutes` | 60 | 趋势图统计的分钟数 |
| `top_ips` | 8 | 统计页展示的来源 IP Top 数 |
| `log_field_max` | 160 | 攻击日志单字段（URI / UA）最大长度 |
| `stats_prefix` | `/security` | 统计页前缀 |
| `dict_name` | `openlitewaf` | 须与 `lua_shared_dict` 名一致 |

CC 阈值与 nginx 静态限速有联动关系：`limit_req`（PREACCESS 阶段）先于本模块（ACCESS 阶段）执行，超额请求以 503 丢弃、不进入计数，因此 `cc.limit` 折算（`limit / window`）必须低于 `limit_req` 速率，否则 CC 分支不会被触发。调整任一侧时检查另一侧。短时高频脉冲会被 `limit_req` 直接丢弃，不会计入本模块。该联动只对经 `location /` 反代的请求成立：`/security`、`/stats` 一类由 Lua 直接响应的精确 location 没有 `limit_req`，它们的超额完全由 CC 承担（含 nginx healthcheck 每 30 秒一次的内部探测，量级可忽略）。

## 规则

规则定义在 `lua/openlitewaf.lua` 的 `_M.RULES`，位于 `-- RULES-BEGIN` / `-- RULES-END` 标记之间，每条为 `{ "类目", [[PCRE]] }` 或 `{ "类目", [[PCRE]], "作用域" }`，类目为小写字母：`sqli`、`xss`、`traversal`、`rce`、`probe`；作用域为 `uri` / `path` / `ua` / `body` 的空格分隔组合，省略表示作用于全部匹配对象。正则使用 ngx.re 语法，编译 flags 为 `ji`（忽略大小写 + JIT）。

编写时注意：规则必须保持单行表，`tests/openlitewaf_regex_test.php` 按 `RULES-BEGIN/END` 标记与该格式解析，并会在解析条数少于块内声明条数时直接失败退出（防止新写法把规则静默漏出回归）；规则内容含 `]]` 时（如字符类 `[a-z]` 结尾），Lua 长括号改用 `[==[ ]==]`；规则按顺序匹配、命中即停，新增规则的位置影响计数归属；路径形态的特征不要标成全部对象，否则又会开始封误封；修改或新增规则时，同步在 `tests/openlitewaf_regex_test.php` 补充正样本（应拦截）与反样本（不应拦截），并按匹配对象分类——该文件把 URI（含路径与 query）、UA、body 三类样本分别标注 kind，用来验证作用域本身。

URI 侧样本按生产的两个匹配对象依次求值：规则标 `uri` 时看原始与解码 `request_uri`（含 query），标 `path` 时只看截断 query 后的路径。body 与 UA 的作用域只能由 `openlitewaf_logic_test.lua` 的流程用例覆盖（那里 stub 掉了 `ngx.re`，只验证"哪条规则参与了哪个对象"，不验证正则本身），真实 ngx.re + 真实 body 的端到端验证在主仓 `scripts/ci_e2e_test.php --waf-test`。

回归测试与语法检查：

```bash
php OpenLiteWaf/tests/openlitewaf_regex_test.php    # 规则正负样本（PHP PCRE，与 ngx.re 同源）
lua5.1 OpenLiteWaf/tests/openlitewaf_logic_test.lua # 检查流程/CC/体检查/日志/统计逻辑（stub ngx）
luac5.1 -p OpenLiteWaf/lua/*.lua                    # 语法检查
```

## 注意事项

规则只覆盖已知特征，语义层攻击与定向利用不在防护范围。限速与日志按 IP 维度统计，NAT 与共享出口会造成误伤；nginx 前存在 CDN 或负载均衡时，`remote_addr` 是节点 IP，需先配置 nginx `real_ip` 模块并只信任已知代理，否则 CC 计数与日志 IP 均不准确。本模块无 IP 信誉库、无 JS 挑战、无 GeoIP 定位（趋势图为本站数据），高强度抗 CC 依赖前置 CDN/WAF。

CC 计数超过 `cc.limit` 时返回 429 + `Retry-After`，不写封禁名单：计数键按窗口分桶，超限期间同一窗口持续 429，跨窗口自动恢复。CC 不是攻击证据，把移动网络共享出口整片封掉只会制造大面积不可用。

误封的现实代价主要由两点决定：封禁按 IP 而非按端点或类目生效，以及单次命中即封。前者保持不变（跨端点封禁是压制扫描器的手段），后者由 `sig_strikes` 缓解——单个正常客户端在窗口内累计命中 3 次的概率极低，而真扫描器几乎必然复读。`blocked_total` 与各类目之和的差值就是封禁期重复拦截数，这个差值突然拉长通常意味着出现了新的误封来源，直接查 `/security/logs` 的 `rule` 与 `via` 字段定位是哪条规则作用在哪个对象上。

## 许可证

MIT，见 [LICENSE](LICENSE)。
