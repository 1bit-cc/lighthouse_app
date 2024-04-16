# 自动更新腾讯云轻量防火墙规则

## 简介

从指定URL获取白名单IP段列表，并自动更新腾讯云轻量防火墙规则。

自动识别IPv4和IPv6地址，白名单IP段列表可以混合两种地址。

自动识别实例地域，只需设置实例ID列表即可。

## 白名单IP段列表格式

如果想要自己下发IP段，请按照以下格式编写白名单IP段列表：

```
1.12.2.0/24
3.2.1.0/24
23.1.23.0/24
```

## 配置文件

配置文件位于`config.json`，各字段含义如下：
- `ApiDomain`：腾讯云API域名，勿动。
- `secretId`：腾讯云API密钥ID，请在腾讯云控制台获取。
- `secretKey`：腾讯云API密钥KEY，请在腾讯云控制台获取。
- `IPListURL`：白名单IP段列表URL，支持HTTP/HTTPS。
- `InstanceId`：腾讯云轻量服务器实例ID列表，请在腾讯云控制台获取。
- `sleepTime`：更新间隔，单位为秒。
- `pushMsgOpen`：是否开启推送消息，0为关闭，1为开启。
- `workWxWebHook`：企业微信群聊机器人WebHook，请在企业微信群中新建并获取。

## 部署

可选Docker部署和本机直接运行

### Docker部署

**请确保本机安装了Docker和Docker Compose。**

```bash
git clone https://github.com/1bit-cc/lighthouse_app.git
cd lighthouse_app/autoUpdateFirewallRules
docker build -t lh_aufr:0.1 .
```

打开`config.json`，修改配置文件。

```bash
docker-compose up -d
```

### 本机直接运行

**请确保本机安装了Python3.6及以上版本。**

```bash
git clone https://github.com/1bit-cc/lighthouse_app.git
cd lighthouse_app/autoUpdateFirewallRules
pip install -r requirements.txt
```
打开`config.json`，修改配置文件。
```bash
python main.py
```
