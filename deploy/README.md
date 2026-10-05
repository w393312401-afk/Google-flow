# Flow2API 公网入口

公网入口使用 Cloudflare Tunnel，经独立网关转发到现有本机服务：

```text
https://flow2api.wushi-api.com
  → Cloudflare Tunnel: spark-mac
  → http://127.0.0.1:38001（公网网关）
  → http://127.0.0.1:38000（现有 Flow2API）
```

OpenAI 兼容 Base URL 为 `https://flow2api.wushi-api.com/v1`，Gemini Base URL 为 `https://flow2api.wushi-api.com/v1beta`。公网管理员密码和 API Key 独立于本机凭据，保存在 `/Users/fly/Library/Application Support/Flow2API/public-access/credentials.txt`；配置保存在同目录 `config.json`。目录权限为 0700，凭据文件为 0600，不进入 Git。

网关验证公网 API Key 后读取 SQLite 中现有 API Key并转发，公网管理员登录同样使用独立强密码。原服务和 SPARK 的本机配置保持不变。公网后台显示的是公网 API Key；修改管理员密码、API Key 和缓存基础地址的操作在公网入口被禁止，需要在本机维护。

网关使用固定的 HTTPS 主机头生成公网媒体链接，保持原服务 `cache_base_url` 为空，避免影响 SPARK 的本机媒体下载。缓存媒体链接沿用原服务的访问方式：持有文件链接即可访问，按原缓存期限过期。公网不提供 `/metrics`、`/captcha_ws` 和自动 API 文档；健康检查只返回服务是否在线。

网关由 `/Users/fly/Library/LaunchAgents/com.fly.flow2api.public-gateway.plist` 管理。电脑必须保持开机、用户已登录、联网，且本机 Flow2API 和 `spark-mac` 隧道运行。此部署提供固定公网地址，计算和浏览器仍在 Mac 上运行。

检查网关：

```sh
launchctl print "gui/$(id -u)/com.fly.flow2api.public-gateway"
curl --noproxy '*' http://127.0.0.1:38001/health
```

仅重启网关：

```sh
launchctl kickstart -k "gui/$(id -u)/com.fly.flow2api.public-gateway"
```

暂停公网入口，不停止本机 Flow2API 或 SPARK：

```sh
launchctl bootout "gui/$(id -u)/com.fly.flow2api.public-gateway"
```

重新启动：

```sh
launchctl bootstrap "gui/$(id -u)" /Users/fly/Library/LaunchAgents/com.fly.flow2api.public-gateway.plist
```

日志位于 `/Users/fly/Library/Application Support/Flow2API/public-access/gateway.log` 和 `gateway-error.log`。关闭了 HTTP 访问日志，以避免记录通过查询参数传入的 API Key。

离线验证：

```sh
.venv/bin/python -m unittest tests.test_public_gateway -v
```
