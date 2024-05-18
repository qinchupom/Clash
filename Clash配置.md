# [Rules 规则](https://a76yyyy.github.io/clash/zh_CN/configuration/rules.html)
> 在快速入手中, 我们介绍了Clash中基于规则的匹配的基本知识. 在本章中, 我们将介绍最新版本的 Clash 中所有可用的规则类型.

```list
# 类型,参数,策略(,no-resolve)
TYPE,ARGUMENT,POLICY(,no-resolve)
```
`no-resolve`选项是可选的, 它用于跳过规则的 DNS 解析. 当您想要使用 `GEOIP`、`IP-CIDR`、`IP-CIDR6`、`SCRIPT` 规则, 但又不想立即将域名解析为 IP 地址时, 这个选项就很有用了.

- [Rules 规则](#rules-规则)
  - [策略](#策略)
  - [规则类型](#规则类型)
    - [DOMAIN 域名](#domain-域名)
    - [DOMAIN-SUFFIX 域名后缀](#domain-suffix-域名后缀)
    - [DOMAIN-KEYWORD 域名关键字](#domain-keyword-域名关键字)
    - [GEOIP IP地理位置 (国家代码)](#geoip-ip地理位置-国家代码)
    - [IP-CIDR IPv4地址段](#ip-cidr-ipv4地址段)
    - [IP-CIDR6 IPv6地址段](#ip-cidr6-ipv6地址段)
    - [SRC-IP-CIDR 源IP段地址](#src-ip-cidr-源ip段地址)
    - [SRC-PORT 源端口](#src-port-源端口)
    - [DST-PORT 目标端口](#dst-port-目标端口)
    - [PROCESS-NAME 源进程名](#process-name-源进程名)
    - [PROCESS-PATH 源进程路径](#process-path-源进程路径)
    - [IPSET IP集(*仅Linux*)](#ipset-ip集仅linux)
    - [RULE-SET 规则集](#rule-set-规则集)
    - [SCRIPT 脚本](#script-脚本)
    - [MATCH 全匹配](#match-全匹配)
- [Rule Providers 规则集](#rule-providers-规则集)
  - [`domain`](#domain)
  - [`ipcidr`](#ipcidr)
  - [`classical`](#classical)
- [Clash DNS](#clash-dns)
  - [fake-ip](#fake-ip)
- [参考配置](#参考配置)

## 策略
目前有四种策略类型, 其中:- [Rules 规则](#rules-规则)
- DIRECT: 通过 `interface-name` 直接连接到目标 (不查找系统路由表)
- REJECT: 丢弃数据包
- Proxy: 将数据包路由到指定的代理服务器
- Proxy Group: 将数据包路由到指定的策略组

## 规则类型
以下部分介绍了每种规则类型及其使用方法:

### DOMAIN 域名
`DOMAIN,www.google.com,policy` 将 `www.google.com` 路由到 `policy`.

### DOMAIN-SUFFIX 域名后缀
`DOMAIN-SUFFIX,youtube.com,policy` 将任何以 `youtube.com` 结尾的域名路由到 `policy`.

在这种情况下, `www.youtube.com` 和 `foo.bar.youtube.com` 都将路由到 `policy`.

### DOMAIN-KEYWORD 域名关键字
`DOMAIN-KEYWORD,google,policy` 将任何包含 `google` 关键字的域名路由到 `policy`.

在这种情况下, `www.google.com` 或 `googleapis.com` 都将路由到 `policy`.

### GEOIP IP地理位置 (国家代码)
GEOIP 规则用于根据数据包的目标 IP 地址的**国家代码**路由数据包. Clash 使用 [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) 数据库来实现这一功能.

> <font color=#d1a336> **Warning**<br>
> 使用这种规则时, Clash 将域名解析为 IP 地址, 然后查找 IP 地址的国家代码. 如果要跳过 DNS 解析, 请使用 `no-resolve` 选项.
> </font>

`GEOIP,CN,policy` 将任何目标 IP 地址为中国的数据包路由到 `policy`.

### IP-CIDR IPv4地址段
IP-CIDR 规则用于根据数据包的目标 IPv4 地址路由数据包.

> <font color=#d1a336> **Warning**<br>
> 使用这种规则时, Clash 将域名解析为 IPv4 地址. 如果要跳过 DNS 解析, 请使用 `no-resolve` 选项.
> </font>

`IP-CIDR,127.0.0.0/8,DIRECT` 将任何目标 IP 地址为 127.0.0.0/8 的数据包路由到 `DIRECT`.

### IP-CIDR6 IPv6地址段
IP-CIDR6 规则用于根据数据包的目标 IPv6 地址路由数据包.

> <font color=#d1a336> **Warning**<br>
> 使用这种规则时, Clash 将域名解析为 IPv6 地址. 如果要跳过 DNS 解析, 请使用 `no-resolve` 选项.
> </font>

`IP-CIDR6,2620:0:2d0:200::7/32,policy` 将任何目标 IP 地址为 2620:0:2d0:200::7/32 的数据包路由到 `policy`.

### SRC-IP-CIDR 源IP段地址
SRC-IP-CIDR 规则用于根据数据包的源 IPv4 地址路由数据包.

`SRC-IP-CIDR,192.168.1.201/32,DIRECT` 将任何源 IP 地址为 192.168.1.201/32 的数据包路由到 `DIRECT`.

### SRC-PORT 源端口
SRC-PORT 规则用于根据数据包的源端口路由数据包.

`SRC-PORT,80,policy` 将任何源端口为 80 的数据包路由到 `policy`.

### DST-PORT 目标端口
DST-PORT 规则用于根据数据包的目标端口路由数据包.

`DST-PORT,80,policy` 将任何目标端口为 80 的数据包路由到 `policy`.

### PROCESS-NAME 源进程名
PROCESS-NAME 规则用于根据发送数据包的进程名称路由数据包.

> <font color=#d1a336> **Warning**<br>
> 目前, 仅支持 macOS、Linux、FreeBSD 和 Windows.
> </font>

`PROCESS-NAME,nc,DIRECT` 将任何来自进程 nc 的数据包路由到 `DIRECT`.

### PROCESS-PATH 源进程路径
PROCESS-PATH 规则用于根据发送数据包的进程路径路由数据包.

> <font color=#d1a336> **Warning**<br>
> 目前, 仅支持 macOS、Linux、FreeBSD 和 Windows.
> </font>

`PROCESS-PATH,/usr/local/bin/nc,DIRECT` 将任何来自路径为 /usr/local/bin/nc 的进程的数据包路由到 `DIRECT`.

### IPSET IP集(*仅Linux*)
IPSET 规则用于根据 IP 集匹配并路由数据包. 根据 IPSET 的官方网站 的介绍:

> IP 集是 Linux 内核中的一个框架, 可以通过 ipset 程序进行管理. 根据类型, IP 集可以存储 IP 地址、网络、 (TCP/UDP) 端口号、MAC 地址、接口名称或它们以某种方式的组合, 以确保在集合中匹配条目时具有闪电般的速度.

因此, 此功能仅在 **Linux** 上工作, 并且需要安装 `ipset`.

> <font color=#d1a336> **Warning**<br>
> 使用此规则时, Clash 将解析域名以获取 IP 地址, 然后查找 IP 地址是否在 IP 集中. 如果要跳过 DNS 解析, 请使用 `no-resolve` 选项.
> </font>

`IPSET,chnroute,policy` 将任何目标 IP 地址在 IP 集 chnroute 中的数据包路由到 `policy`.

### [RULE-SET 规则集](https://a76yyyy.github.io/clash/zh_CN/configuration/rules.html#rule-set-%E8%A7%84%E5%88%99%E9%9B%86)

RULE-SET 规则用于根据 [Rule Providers 规则集](https://a76yyyy.github.io/clash/zh_CN/premium/rule-providers.html) 的结果路由数据包. 当 Clash 使用此规则时, 它会从指定的 Rule Providers 规则集中加载规则, 然后将数据包与规则进行匹配. 如果数据包与任何规则匹配, 则将数据包路由到指定的策略, 否则跳过此规则.

> <font color=#d1a336> **Warning**<br>
> 使用 RULE-SET 时, 当规则集的类型为 IPCIDR , Clash 将解析域名以获取 IP 地址. 如果要跳过 DNS 解析, 请使用 `no-resolve` 选项.
> </font>

`RULE-SET,my-rule-provider,DIRECT` 从 `my-rule-provider` 加载所有规则

### [SCRIPT 脚本](https://a76yyyy.github.io/clash/zh_CN/configuration/rules.html#script-%E8%84%9A%E6%9C%AC)

SCRIPT 规则用于根据脚本的结果路由数据包. 当 Clash 使用此规则时, 它会执行指定的脚本, 然后将数据包路由到脚本的输出.

> <font color=#d1a336> **Warning**<br>
> 使用 SCRIPT 时, Clash 将解析域名以获取 IP 地址. 如果要跳过 DNS 解析, 请使用 `no-resolve` 选项.
> </font>

`SCRIPT,script-path,DIRECT` 将数据包路由到脚本 `script-path` 的输出.

### MATCH 全匹配

MATCH 规则用于路由剩余的数据包. 该规则是必需的, 通常用作最后一条规则.

`MATCH,DIRECT` 将剩余的数据包路由到 `DIRECT`

# [Rule Providers 规则集](https://a76yyyy.github.io/clash/zh_CN/premium/rule-providers.html)

Rule Providers 规则集和 [Proxy Providers 代理集](https://a76yyyy.github.io/clash/zh_CN/configuration/outbound.html#proxy-providers-%E4%BB%A3%E7%90%86%E9%9B%86) 基本相同. 使用户可以动态加载代理服务器列表, 而不是在配置文件中硬编码.

要定义 Rule Providers 规则集, 请将 `rule-providers` 规则集字段添加到主配置中:

```yaml
rule-providers:
  apple:
    behavior: "domain" # domain, ipcidr or classical (仅限 Clash Premium 内核)
    type: http
    url: "url"
    # format: 'yaml' # or 'text'
    interval: 3600
    path: ./apple.yaml
  microsoft:
    behavior: "domain"
    type: file
    path: /microsoft.yaml

rules:
  - RULE-SET,apple,REJECT
  - RULE-SET,microsoft,policy
  ```

有三种行为类型可用:

## `domain`

```yaml
payload:
  - '.blogger.com'
  - '*.*.microsoft.com'
  - 'books.itunes.apple.com'
```
```txt
# comment
.blogger.com
*.*.microsoft.com
books.itunes.apple.com
```
## `ipcidr`

```yaml
payload:
  - '192.168.1.0/24'
  - '10.0.0.0.1/32'
```
```txt
# comment
192.168.1.0/24
10.0.0.0.1/32
```

## `classical`

```yaml
payload:
  - DOMAIN-SUFFIX,google.com
  - DOMAIN-KEYWORD,google
  - DOMAIN,ad.com
  - SRC-IP-CIDR,192.168.1.201/32
  - IP-CIDR,127.0.0.0/8
  - GEOIP,CN
  - DST-PORT,80
  - SRC-PORT,7777
  # MATCH 在这里并不是必须的
```
```txt
# comment
DOMAIN-SUFFIX,google.com
DOMAIN-KEYWORD,google
DOMAIN,ad.com
SRC-IP-CIDR,192.168.1.201/32
IP-CIDR,127.0.0.0/8
GEOIP,CN
```

# [Clash DNS](https://a76yyyy.github.io/clash/zh_CN/configuration/dns.html)

由于 Clash 的某些部分运行在第 3 层 (网络层) , 因此其数据包的域名是无法获取的, 也就无法进行基于规则的路由.

**Enter fake-ip**: 它支持基于规则的路由, 最大程度地减少了 DNS 污染攻击的影响, 并且提高了网络性能, 有时甚至是显著的.

## fake-ip
"fake IP" 的概念源自 RFC 3089:

> 一个 "fake IP" 地址被用于查询相应的 "FQDN" 信息的关键字.

fake-ip 池的默认 CIDR 是 `198.18.0.1/16 `(一个保留的 IPv4 地址空间, 可以在 `dns.fake-ip-range` 中进行更改).

当 DNS 请求被发送到 Clash DNS 时, Clash 内核会通过管理内部的域名和其 fake-ip 地址的映射, 从池中分配一个 空闲 的 fake-ip 地址.

以使用浏览器访问 `http://google.com` 为例.

浏览器向 Clash DNS 请求 `google.com` 的 IP 地址

Clash 检查内部映射并返回 `198.18.1.5`

浏览器向 `198.18.1.5` 的 `80/tcp` 端口发送 HTTP 请求

当收到 `198.18.1.5` 的入站数据包时, Clash 查询内部映射, 发现客户端实际上是在向 `google.com` 发送数据包

根据规则的不同:

Clash 可能仅将域名发送到 SOCKS5 或 shadowsocks 等出站代理, 并与代理服务器建立连接

或者 Clash 可能会基于 `SCRIPT`、`GEOIP`、`IP-CIDR` 规则或者使用 `DIRECT` 直连出口查询 `google.com` 的真实 IP 地址

由于这是一个令人困惑的概念, 我将以使用 cURL 程序访问 `http://google.com` 为例:


```sh
$ curl -v http://google.com
<---- cURL 向您的系统 DNS (Clash) 询问 google.com 的 IP 地址
----> Clash 决定使用 198.18.1.70 作为 google.com 的 IP 地址, 并记住它
*   Trying 198.18.1.70:80...
<---- cURL 连接到 198.18.1.70 tcp/80
----> Clash 将立即接受连接, 并且..
* Connected to google.com (198.18.1.70) port 80 (#0)
----> Clash 在其内存中查找到 198.18.1.70 对应于 google.com
----> Clash 查询对应的规则, 并通过匹配的出口发送数据包
> GET / HTTP/1.1
> Host: google.com
> User-Agent: curl/8.0.1
> Accept: */*
>
< HTTP/1.1 301 Moved Permanently
< Location: http://www.google.com/
< Content-Type: text/html; charset=UTF-8
< Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-ahELFt78xOoxhySY2lQ34A' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
< Date: Thu, 11 May 2023 06:52:19 GMT
< Expires: Sat, 10 Jun 2023 06:52:19 GMT
< Cache-Control: public, max-age=2592000
< Server: gws
< Content-Length: 219
< X-XSS-Protection: 0
< X-Frame-Options: SAMEORIGIN
<
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://www.google.com/">here</A>.
</BODY></HTML>
* Connection #0 to host google.com left intact
```

# [参考配置](https://a76yyyy.github.io/clash/zh_CN/configuration/configuration-reference.html)

```yaml
# HTTP(S) 代理服务端口
port: 7890

# SOCKS5 代理服务端口
socks-port: 7891

# Linux 和 macOS 的透明代理服务端口 (TCP 和 TProxy UDP 重定向)
# redir-port: 7892

# Linux 的透明代理服务端口 (TProxy TCP 和 TProxy UDP)
# tproxy-port: 7893

# HTTP(S) 和 SOCKS4(A)/SOCKS5 代理服务共用一个端口
# mixed-port: 7890

# 本地 SOCKS5/HTTP(S) 代理服务的认证
# authentication:
#  - "user1:pass1"
#  - "user2:pass2"

# 设置为 true 以允许来自其他 LAN IP 地址的连接
# allow-lan: false

# 仅当 `allow-lan` 为 `true` 时有效
# '*': 绑定所有 IP 地址
# 192.168.122.11: 绑定单个 IPv4 地址
# "[aaaa::a8aa:ff:fe09:57d8]": 绑定单个 IPv6 地址
# bind-address: '*'

# Clash 路由工作模式
# rule: 基于规则的数据包路由
# global: 所有数据包将被转发到单个节点
# direct: 直接将数据包转发到互联网
mode: rule

# 默认情况下, Clash 将日志打印到 STDOUT
# 日志级别: info / warning / error / debug / silent
# log-level: info

# 当设置为 false 时, 解析器不会将主机名解析为 IPv6 地址
# ipv6: false

# RESTful Web API 监听地址
external-controller: 127.0.0.1:9090

# 配置目录的相对路径或静态 Web 资源目录的绝对路径. Clash core 将在
# `http://{{external-controller}}/ui` 中提供服务.
# external-ui: folder

# RESTful API 密钥 (可选)
# 通过指定 HTTP 头 `Authorization: Bearer ${secret}` 进行身份验证
# 如果RESTful API在 0.0.0.0 上监听, 务必设置一个 secret 密钥.
# secret: ""

# 出站接口名称
# interface-name: en0

# fwmark (仅在 Linux 上有效)
# routing-mark: 6666

# 用于DNS服务器和连接建立的静态主机 (如/etc/hosts) .
#
# 支持通配符主机名 (例如 *.clash.dev, *.foo.*.example.com)
# 非通配符域名优先级高于通配符域名
# 例如 foo.example.com > *.example.com > .example.com
# P.S. +.foo.com 等于 .foo.com 和 foo.com
# hosts:
  # '*.clash.dev': 127.0.0.1
  # '.dev': 127.0.0.1
  # 'alpha.clash.dev': '::1'

# profile:
  # 将 `select` 手动选择 结果存储在 $HOME/.config/clash/.cache 中
  # 如果不需要此行为, 请设置为 false
  # 当两个不同的配置具有同名的组时, 将共享所选值
  # store-selected: true

  # 持久化 fakeip
  # store-fake-ip: false

# DNS 服务设置
# 此部分是可选的. 当不存在时, DNS 服务将被禁用.
dns:
  enable: false
  listen: 0.0.0.0:53
  # ipv6: false # 当为 false 时, AAAA 查询的响应将为空

  # 这些 名称服务器(nameservers) 用于解析下列 DNS 名称服务器主机名.
  # 仅指定 IP 地址
  default-nameserver:
    - 114.114.114.114
    - 8.8.8.8
  # enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16 # Fake IP 地址池 CIDR
  # use-hosts: true # 查找 hosts 并返回 IP 记录

  # search-domains: [local] # A/AAAA 记录的搜索域

  # 此列表中的主机名将不会使用 Fake IP 解析
  # 即, 对这些域名的请求将始终使用其真实 IP 地址进行响应
  # fake-ip-filter:
  #   - '*.lan'
  #   - localhost.ptlogin2.qq.com

  # 支持 UDP、TCP、DoT、DoH. 您可以指定要连接的端口.
  # 所有 DNS 查询都直接发送到名称服务器, 无需代理
  # Clash 使用第一个收到的响应作为 DNS 查询的结果.
  nameserver:
    - 114.114.114.114 # 默认值
    - 8.8.8.8 # 默认值
    - tls://dns.rubyfish.cn:853 # DNS over TLS
    - https://1.1.1.1/dns-query # DNS over HTTPS
    - dhcp://en0 # 来自 dhcp 的 dns
    # - '8.8.8.8#en0'

  # 当 `fallback` 存在时, DNS 服务器将向此部分中的服务器
  # 与 `nameservers` 中的服务器发送并发请求
  # 当 GEOIP 国家不是 `CN` 时, 将使用 fallback 服务器的响应
  # fallback:
  #   - tcp://1.1.1.1
  #   - 'tcp://1.1.1.1#en0'

  # 如果使用 `nameservers` 解析的 IP 地址在下面指定的子网中,
  # 则认为它们无效, 并使用 `fallback` 服务器的结果.
  #
  # 当 `fallback-filter.geoip` 为 true 且 IP 地址的 GEOIP 为 `CN` 时,
  # 将使用 `nameservers` 服务器解析的 IP 地址.
  #
  # 如果 `fallback-filter.geoip` 为 false, 且不匹配 `fallback-filter.ipcidr`,
  # 则始终使用 `nameservers` 服务器的结果
  #
  # 这是对抗 DNS 污染攻击的一种措施.
  # fallback-filter:
  #   geoip: true
  #   geoip-code: CN
  #   ipcidr:
  #     - 240.0.0.0/4
  #   domain:
  #     - '+.google.com'
  #     - '+.facebook.com'
  #     - '+.youtube.com'

  # 通过特定的名称服务器查找域名
  # nameserver-policy:
  #   'www.baidu.com': '114.114.114.114'
  #   '+.internal.crop.com': '10.0.0.1'

proxies:
  # Shadowsocks
  # 支持的加密方法:
  #   aes-128-gcm aes-192-gcm aes-256-gcm
  #   aes-128-cfb aes-192-cfb aes-256-cfb
  #   aes-128-ctr aes-192-ctr aes-256-ctr
  #   rc4-md5 chacha20-ietf xchacha20
  #   chacha20-ietf-poly1305 xchacha20-ietf-poly1305
  - name: "ss1"
    type: ss
    server: server
    port: 443
    cipher: chacha20-ietf-poly1305
    password: "password"
    # udp: true

  - name: "ss2"
    type: ss
    server: server
    port: 443
    cipher: chacha20-ietf-poly1305
    password: "password"
    plugin: obfs
    plugin-opts:
      mode: tls # or http
      # host: bing.com

  - name: "ss3"
    type: ss
    server: server
    port: 443
    cipher: chacha20-ietf-poly1305
    password: "password"
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket # 暂不支持 QUIC
      # tls: true # wss
      # skip-cert-verify: true
      # host: bing.com
      # path: "/"
      # mux: true
      # headers:
      #   custom: value

  # vmess
  # 支持的加密方法:
  #  auto/aes-128-gcm/chacha20-poly1305/none
  - name: "vmess"
    type: vmess
    server: server
    port: 443
    uuid: uuid
    alterId: 32
    cipher: auto
    # udp: true
    # tls: true
    # skip-cert-verify: true
    # servername: example.com # 优先于 wss 主机
    # network: ws
    # ws-opts:
    #   path: /path
    #   headers:
    #     Host: v2ray.com
    #   max-early-data: 2048
    #   early-data-header-name: Sec-WebSocket-Protocol

  - name: "vmess-h2"
    type: vmess
    server: server
    port: 443
    uuid: uuid
    alterId: 32
    cipher: auto
    network: h2
    tls: true
    h2-opts:
      host:
        - http.example.com
        - http-alt.example.com
      path: /

  - name: "vmess-http"
    type: vmess
    server: server
    port: 443
    uuid: uuid
    alterId: 32
    cipher: auto
    # udp: true
    # network: http
    # http-opts:
    #   # method: "GET"
    #   # path:
    #   #   - '/'
    #   #   - '/video'
    #   # headers:
    #   #   Connection:
    #   #     - keep-alive

  - name: vmess-grpc
    server: server
    port: 443
    type: vmess
    uuid: uuid
    alterId: 32
    cipher: auto
    network: grpc
    tls: true
    servername: example.com
    # skip-cert-verify: true
    grpc-opts:
      grpc-service-name: "example"

  # socks5
  - name: "socks"
    type: socks5
    server: server
    port: 443
    # username: username
    # password: password
    # tls: true
    # skip-cert-verify: true
    # udp: true

  # http
  - name: "http"
    type: http
    server: server
    port: 443
    # username: username
    # password: password
    # tls: true # https
    # skip-cert-verify: true
    # sni: custom.com

  # Snell
  # 请注意, 目前还没有UDP支持.
  - name: "snell"
    type: snell
    server: server
    port: 44046
    psk: yourpsk
    # version: 2
    # obfs-opts:
      # mode: http # or tls
      # host: bing.com

  # Trojan
  - name: "trojan"
    type: trojan
    server: server
    port: 443
    password: yourpsk
    # udp: true
    # sni: example.com # aka 服务器名称
    # alpn:
    #   - h2
    #   - http/1.1
    # skip-cert-verify: true

  - name: trojan-grpc
    server: server
    port: 443
    type: trojan
    password: "example"
    network: grpc
    sni: example.com
    # skip-cert-verify: true
    udp: true
    grpc-opts:
      grpc-service-name: "example"

  - name: trojan-ws
    server: server
    port: 443
    type: trojan
    password: "example"
    network: ws
    sni: example.com
    # skip-cert-verify: true
    udp: true
    # ws-opts:
      # path: /path
      # headers:
      #   Host: example.com

  # ShadowsocksR
  # 支持的加密方法: ss 中的所有流加密方法
  # 支持的混淆方式:
  #   plain http_simple http_post
  #   random_head tls1.2_ticket_auth tls1.2_ticket_fastauth
  # 支持的协议:
  #   origin auth_sha1_v4 auth_aes128_md5
  #   auth_aes128_sha1 auth_chain_a auth_chain_b
  - name: "ssr"
    type: ssr
    server: server
    port: 443
    cipher: chacha20-ietf
    password: "password"
    obfs: tls1.2_ticket_auth
    protocol: auth_sha1_v4
    # obfs-param: domain.tld
    # protocol-param: "#"
    # udp: true

proxy-groups:
  # 中继链路代理节点. 节点不应包含中继. 不支持 UDP.
  # 流量节点链路: clash <-> http <-> vmess <-> ss1 <-> ss2 <-> Internet
  - name: "relay"
    type: relay
    proxies:
      - http
      - vmess
      - ss1
      - ss2

  # url-test 通过对 指定URL 进行基准速度测试来选择将使用哪个代理.
  - name: "auto"
    type: url-test
    proxies:
      - ss1
      - ss2
      - vmess1
    # tolerance: 150
    # lazy: true
    url: 'http://www.gstatic.com/generate_204'
    interval: 300

  # fallback-auto 基于优先级选择可用策略. 可用性通过访问 指定URL 来测试, 就像自动 url-test 组一样.
  - name: "fallback-auto"
    type: fallback
    proxies:
      - ss1
      - ss2
      - vmess1
    url: 'http://www.gstatic.com/generate_204'
    interval: 300

  # 负载均衡: 同一 eTLD+1 的请求将拨号到同一代理.
  - name: "load-balance"
    type: load-balance
    proxies:
      - ss1
      - ss2
      - vmess1
    url: 'http://www.gstatic.com/generate_204'
    interval: 300
    # strategy: consistent-hashing # or round-robin

  # select 手动选择, 用于选择代理或策略组
  # 您可以使用 RESTful API 来切换代理, 建议在GUI中切换.
  - name: Proxy
    type: select
    # disable-udp: true
    # filter: 'someregex'
    proxies:
      - ss1
      - ss2
      - vmess1
      - auto

  # 直接连接到另一个接口名称或 fwmark, 也支持代理
  - name: en1
    type: select
    interface-name: en1
    routing-mark: 6667
    proxies:
      - DIRECT

  - name: UseProvider
    type: select
    use:
      - provider1
    proxies:
      - Proxy
      - DIRECT

proxy-providers:
  provider1:
    type: http
    url: "url"
    interval: 3600
    path: ./provider1.yaml
    health-check:
      enable: true
      interval: 600
      # lazy: true
      url: http://www.gstatic.com/generate_204
  test:
    type: file
    path: /test.yaml
    health-check:
      enable: true
      interval: 36000
      url: http://www.gstatic.com/generate_204

tunnels:
  # 单行配置
  - tcp/udp,127.0.0.1:6553,114.114.114.114:53,proxy
  - tcp,127.0.0.1:6666,rds.mysql.com:3306,vpn
  # 全 yaml 配置
  - network: [tcp, udp]
    address: 127.0.0.1:7777
    target: target.com
    proxy: proxy

rules:
  - DOMAIN-SUFFIX,google.com,auto
  - DOMAIN-KEYWORD,google,auto
  - DOMAIN,google.com,auto
  - DOMAIN-SUFFIX,ad.com,REJECT
  - SRC-IP-CIDR,192.168.1.201/32,DIRECT
  # 用于 IP 规则 (GEOIP, IP-CIDR, IP-CIDR6) 的可选参数 "no-resolve"
  - IP-CIDR,127.0.0.0/8,DIRECT
  - GEOIP,CN,DIRECT
  - DST-PORT,80,DIRECT
  - SRC-PORT,7777,DIRECT
  - RULE-SET,apple,REJECT # 仅 Premium 版本支持
  - MATCH,auto
```