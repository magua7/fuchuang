# magualine-lite

这是一个面向比赛演示场景的最小版 Web 流量防护与运营后台。

## 这套系统能做什么

- 把外部访问代理到你的真实网站
- 检测并拦截常见 Web 攻击
- 记录请求日志和攻击日志
- 支持手动封禁 IP 和解封 IP
- 提供一个简洁的后台管理界面

## 推荐部署方式

1. 让真实业务站点放在这套网关后面。
2. 让你的源站只监听本机地址，例如 `127.0.0.1:8090`。
3. 在 `.env` 里把 `UPSTREAM_URL` 改成你的真实源站地址。
4. 启动整套服务：

```bash
cp .env.example .env
docker compose up -d --build
```

## 访问地址

- 对外流量入口：`http://你的服务器IP/`
- 管理后台：`http://你的服务器IP:9443/`

## 如果你同机部署的是 Halo

如果 Halo 在宿主机上监听的是 `127.0.0.1:8090`，那么 `.env` 里保持下面这项即可：

```env
UPSTREAM_URL=http://host.docker.internal:8090
```

当前 `docker-compose.yml` 已经把 `host.docker.internal` 映射到了 Linux 宿主机网关地址，所以容器里可以直接回源到宿主机上的 Halo。
