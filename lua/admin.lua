-- OpenLiteWaf 运维端点入口：由 docker/nginx/default.conf 中的 content_by_lua_file 调用
-- 解封：POST /security/unban?ip=　封禁清单：GET /security/bans
-- 需 OPENLITEWAF_ADMIN_TOKEN 环境变量（经 nginx env 指令透传给 Lua），未配置时一律 404。
require("openlitewaf").admin()
