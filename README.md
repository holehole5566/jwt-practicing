## 踩到的坑

#### 1. react收的到cookie但是發request的時候沒有戴上 (browser=chrome)

solution: 後端需要用https, set_cookie裡secure=True，可能跟瀏覽器有關

https://github.com/FiloSottile/mkcert



# OAuth2 + JWT + Session 安全筆記

---

## 1. OAuth2 與 JWT 基本流程

### 角色
- **Authorization Server (Auth Server)**：發放 Access Token / ID Token，例如 Google
- **Resource Server**：驗證 Token，提供受保護資源，例如 LINE
- **Client / 前端**：使用者代理，發起登入請求

### 流程
1. 前端導向授權伺服器（Google）進行授權
2. 授權伺服器發放 **JWT**（ID Token / Access Token）
3. 前端將 JWT 送回 Resource Server
4. Resource Server 使用公鑰驗簽：
   - 驗證 token 是授權伺服器簽發
   - 讀取標準 claim：
     - `sub`：使用者唯一 ID
     - `exp`：過期時間
     - `iss`：簽發者
     - `aud`：受眾（client_id）

---

## 2. JWT 签名原理

### JWT 結構
<base64(header)>.<base64(payload)>.<base64(signature)>


### RS256 簽名流程
1. 取 `header.payload` 做 **SHA256 hash**
2. 用 **私鑰 RSA 運算** hash → 產生簽名
3. Base64URL 編碼簽名，作為 JWT 第三段

### 驗簽流程
1. 從 JWT 拆出 `header`、`payload`、`signature`
2. 用同樣方式算 hash
3. 用 **公鑰 RSA 運算** signature → 得到原 hash
4. 比對 hash 是否一致
   - 一致 → JWT 未被竄改，確實由授權伺服器簽發
   - 不一致 → 驗簽失敗

### 注意
- 公鑰無法生成簽名，只能驗簽  
- 私鑰洩漏 → 可偽造 JWT  
- Base64 decode JWT 只看得到 header/payload，不會看到私鑰

---

## 3. JWT 在 OAuth2 場景（以 Google 登入 LINE 為例）
1. Google 登入成功後，發 ID Token（JWT）給 LINE
2. LINE 後端：
   - 從 Google JWKS 下載公鑰
   - 驗簽 JWT（RS256）
   - 成功後讀取 `sub`、`exp` 等 claim
3. 驗簽未通過 → 拒絕
4. JWT decode 不等於驗簽，decode 只能看到內容

---

## 4. 安全性注意點

### 私鑰保密
- RS256 安全依賴私鑰保密
- 私鑰洩漏 → 攻擊者可偽造 JWT，完全破壞安全性

### Cookie / Token 安全
- Cookie 被竊取 → 可偽造身份發請求
- SameSite cookie 防 **CSRF**，但無法防 **XSS / MITM / 裝置入侵**
- HttpOnly + Secure + HTTPS 可降低 JS 竊取和流量截取風險

### 仍存在的風險
- Server 邏輯漏洞（IDOR, Broken Access Control）
- 裝置端被入侵
- 長期 token 或密鑰洩漏
- 社交工程 / 密碼被盜

---

## 5. Session 驗證與 JWT

### Server-side Session
- 前端 cookie 只存 **session ID**（隨機字串）
- Server 存 session 資料（Memory / DB / Redis）
- 過期控制：
  - Server TTL（例如 Redis `SETEX`）
  - Cookie Max-Age / Expires 與 TTL 對應
- 不需要用 JWT 封裝 session ID

### 為什麼不再用 JWT 包 session ID
- JWT 主要優勢是無狀態、自包含
- Server-side session 已有狀態 → JWT 只是額外開銷
- 過期仍要靠 server 控制，JWT 沒增加額外好處

### 安全建議
- HttpOnly + Secure + SameSite cookie
- Server session TTL 控制過期
- Token / session 過期短，避免長期濫用
- 可結合 Access Token + Refresh Token

---

## 6. 防護總結

| 威脅 | 防護措施 |
|------|----------|
| CSRF | SameSite Cookie / CSRF Token |
| XSS 讀 cookie | HttpOnly Cookie / CSP / 輸入驗證 |
| 流量截取 | HTTPS |
| 長期 token 被濫用 | 短期 Access Token + Refresh Token |
| 私鑰洩漏 | 妥善存放在 HSM / Key Vault / 定期輪換 |
| 伺服器邏輯漏洞 | Access Control、IDOR 檢查 |

---

## 7. 範例程式 (Python RS256 驗簽 Google JWT)
```python
import requests
import jwt
from jwt.algorithms import RSAAlgorithm
from jwt import InvalidSignatureError, ExpiredSignatureError, InvalidTokenError

id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRlYj..."  

GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
jwks = requests.get(GOOGLE_JWKS_URL).json()

headers = jwt.get_unverified_header(id_token)
kid = headers["kid"]

public_key = None
for key in jwks["keys"]:
    if key["kid"] == kid:
        public_key = RSAAlgorithm.from_jwk(key)
        break

if not public_key:
    raise Exception("找不到對應的 Google 公鑰")

try:
    payload = jwt.decode(
        id_token,
        public_key,
        algorithms=["RS256"],
        audience="YOUR_LINE_CLIENT_ID",
        issuer="https://accounts.google.com"
    )
    print("驗簽成功，Payload：", payload)

except ExpiredSignatureError:
    print("JWT 已過期")
except InvalidSignatureError:
    print("簽名驗證失敗")
except InvalidTokenError as e:
    print("JWT 無效:", e)
