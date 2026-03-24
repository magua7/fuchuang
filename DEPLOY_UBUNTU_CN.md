# magualine-lite Ubuntu 部署说明

## 1. 先确保真实网站只监听本机

以 Halo 为例：

- 源站地址建议是：`127.0.0.1:8090`
- 不要让 Halo 再占用公网 `80/443`

## 2. 上传项目

把整个 `magualine-lite` 文件夹上传到服务器，例如：

```bash
/opt/magualine-lite
```

## 3. 按需要修改账号或回源地址

编辑这个文件：

```bash
/opt/magualine-lite/.env
```

其中最重要的是这几项：

```env
UPSTREAM_URL=http://host.docker.internal:8090
ADMIN_USERNAME=admin
ADMIN_PASSWORD=Magualine2026!
```

## 4. 启动服务

```bash
cd /opt/magualine-lite
docker compose up -d --build
```

## 5. 访问方式

- 对外流量入口：`http://你的服务器IP/`
- 管理后台：`http://你的服务器IP:9443/`

## 6. 启动后建议检查

- 打开后台并登录
- 通过公网 IP 或域名访问被保护站点
- 看后台里是否已经出现请求日志
- 你也可以手动测试一个简单攻击载荷，例如：

```text
/?id=1%20union%20select%201,2
```

如果拦截正常，后台日志里应该能看到一条新的拦截记录。
