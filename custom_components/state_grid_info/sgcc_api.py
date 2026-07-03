"""
SGCC (State Grid Corporation of China) API client.

Replicates the QingLong state-grid.js login + data fetch flow in Python.
Uses api.120399.xyz proxy for encryption/decryption/risk-control.

Usage:
    async with SgccClient(debug=True) as client:
        await client.login("phone", "password")
        data = await client.fetch_all()

Dependencies: aiohttp
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any, Optional

import aiohttp

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────
PROXY_BASE = "https://api.120399.xyz/wsgw"
SGCC_BASE = "https://www.95598.cn"

BASE_HEADERS = {
    "Content-Type": "application/json;charset=UTF-8",
    "Accept": "application/json;charset=UTF-8",
    "version": "1.0",
    "source": "0901",
    "wsgwType": "web",
}

# Credential expiry error codes (matching Oe function in 95598.js)
EXPIRED_CODES = frozenset({10010, 30010, 10015, 10108, 10009, 10207, 10005, 20103})
EXPIRED_KEYWORDS = ("无效", "失效", "过期", "重新获取", "请求异常", "Token 为空", "WEB渠道KeyCode已失效")

# API paths
API = {
    "keyCode": "/api/oauth2/outer/c02/f02",
    "login": "/api/osg-web0004/open/c44/f06",
    "authorize": "/api/oauth2/oauth/authorize",
    "webToken": "/api/oauth2/outer/getWebToken",
    "bindInfo": "/api/osg-open-uc0001/member/c9/f02",
    "balance": "/api/osg-open-bc0001/member/c05/f01",
    "usage": "/api/osg-web0004/member/c24/f01",
}


# ── Data classes ──────────────────────────────────────────────────────
@dataclass
class LoginState:
    bizrt: dict[str, Any] = field(default_factory=dict)
    access_token: str = ""
    key_code_data: dict[str, Any] = field(default_factory=dict)
    user_info: dict[str, Any] = field(default_factory=dict)

    @property
    def token(self) -> str:
        return self.bizrt.get("token", "")

    @property
    def key_code(self) -> str:
        return self.key_code_data.get("keyCode", "")

    @property
    def public_key(self) -> str:
        return self.key_code_data.get("publicKey", "")

    @property
    def user_id(self) -> str:
        return self.user_info.get("userId") or self.user_info.get("accountId") or self.user_info.get("acctId", "")

    @property
    def user_name(self) -> str:
        return self.user_info.get("realName") or self.user_info.get("nickname") or ""


# ── Client ────────────────────────────────────────────────────────────
class SgccError(Exception):
    """SGCC API error."""


class SgccAuthError(SgccError):
    """Authentication/credential error — needs re-login."""


class SgccClient:
    """Async SGCC API client using api.120399.xyz encryption proxy."""

    def __init__(self, debug: bool = False, timeout: int = 60) -> None:
        self.debug = debug
        self.timeout = timeout
        self._session: Optional[aiohttp.ClientSession] = None
        self._device_token: str = ""
        self._state: LoginState = LoginState()

    async def __aenter__(self) -> "SgccClient":
        connector = aiohttp.TCPConnector(limit=5)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()

    # ── HTTP helpers ──────────────────────────────────────────────
    async def _post(self, url: str, json_data: Any = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
        """POST JSON, return parsed response body."""
        hdrs = headers or {}
        self._log_debug(f"POST {url}")
        async with self._session.post(url, json=json_data, headers=hdrs) as resp:  # type: ignore[arg-type]
            text = await resp.text()
            if resp.status >= 400:
                raise SgccError(f"HTTP {resp.status}: {text[:200]}")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"_raw": text}

    async def _post_sgcc(self, url: str, headers: dict[str, Any], body: str) -> dict[str, Any]:
        """POST to SGCC server (already-encrypted request)."""
        self._log_debug(f"SGCC POST {url}")
        # Ensure all header keys/values are strings (proxy may return ints)
        safe_headers = {str(k): str(v) for k, v in headers.items()}
        async with self._session.post(url, headers=safe_headers, data=body) as resp:
            text = await resp.text()
            if resp.status >= 400:
                raise SgccError(f"SGCC HTTP {resp.status}: {text[:200]}")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"_raw": text}

    def _log_debug(self, msg: str) -> None:
        if self.debug:
            logger.debug(msg)

    def _log(self, msg: str) -> None:
        logger.info(msg)

    # ── Risk context ──────────────────────────────────────────────
    async def _get_risk_context(self) -> None:
        """Fetch risk-control device token from proxy /s4."""
        self._log("获取风控token...")
        resp = await self._post(
            f"{PROXY_BASE}/s4",
            json_data={
                "yuheng": {
                    "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "href": "https://www.95598.cn/osgweb/login",
                    "referer": "https://www.95598.cn/osgweb/login",
                    "ip": "",
                }
            },
        )
        token = resp.get("data", {}).get("tdcItoken", "")
        if not token:
            raise SgccError(f"风控token获取失败: {resp}")
        self._device_token = token
        self._log("风控token获取成功 ✓")

    # ── Encryption proxy ──────────────────────────────────────────
    def _build_headers(self, config_headers: dict[str, str] | None = None) -> dict[str, str]:
        ts = str(int(time.time() * 1000))
        hdrs = {**BASE_HEADERS, "timestamp": ts}
        if config_headers:
            hdrs.update(config_headers)
        return hdrs

    async def _encrypt(self, config: dict[str, Any]) -> dict[str, Any]:
        """Encrypt request via proxy /s1. Returns {url, method, headers, body, encryptKey?}."""
        headers = self._build_headers(config.get("headers"))
        merged = {**config, "headers": headers}
        if self._device_token:
            merged["headers"]["deviceTokenTX"] = self._device_token

        resp = await self._post(f"{PROXY_BASE}/s1", json_data={"yuheng": merged})
        encrypted = resp.get("data", {})
        if not encrypted:
            raise SgccError(f"加密失败: {resp}")

        encrypted["url"] = f"{SGCC_BASE}{encrypted['url']}"

        # Determine body format
        ct = (encrypted.get("headers") or {}).get("Content-Type", "")
        if "x-www-form-urlencoded" in ct:
            encrypted["body"] = encrypted.get("data", "")
        else:
            encrypted["body"] = json.dumps(encrypted.get("data", {}))
        encrypted.pop("data", None)
        return encrypted

    async def _decrypt(self, decrypt_params: dict[str, Any]) -> dict[str, Any]:
        """Decrypt response via proxy /s2."""
        resp = await self._post(f"{PROXY_BASE}/s2", json_data={"yuheng": decrypt_params})
        data = resp.get("data", resp)
        code = data.get("code")
        message = data.get("message", "")

        # Check success (code=1 or absent means success)
        if code is not None and str(code) != "1":
            # RK1003 captcha → need retry
            if str(code) == "RK1003" or "网络连接超时" in message:
                return {"needRetry": True, "code": str(code), "message": message}
            # Credential expiry
            if int(code) in EXPIRED_CODES:
                raise SgccAuthError(message or f"登录态失效 code={code}")
            raise SgccError(message or f"请求失败 code={code}")

        return data.get("data", data)

    async def _sgcc_request(
        self, config: dict[str, Any], *, retry_count: int = 0, max_captcha_retries: int = 3
    ) -> dict[str, Any]:
        """Full encrypt → SGCC → decrypt cycle, with captcha retry."""
        # Encrypt
        encrypted = await self._encrypt(config)

        # Send to SGCC
        sgcc_resp = await self._post_sgcc(
            encrypted["url"],
            headers=encrypted.get("headers", {}),
            body=encrypted["body"],
        )

        # Build decrypt params
        decrypt_params: dict[str, Any] = {"config": config, "data": sgcc_resp}

        # Attach encryptKey for keyCode requests
        if API["keyCode"] in config.get("url", ""):
            decrypt_params["config"]["headers"] = {"encryptKey": encrypted.get("encryptKey", "")}

        # Attach config.data for login
        if config.get("data"):
            decrypt_params["config"]["data"] = config["data"]

        result = await self._decrypt(decrypt_params)

        # Handle RK1003 captcha — retry with captcha params
        if result.get("needRetry") and retry_count < max_captcha_retries:
            self._log(f"RK1003 验证码，第{retry_count + 1}次重试...")
            new_config = {**config}
            if new_config.get("data"):
                import copy
                new_config["data"] = copy.deepcopy(new_config["data"])
                # Navigate to add captcha fields (top-level or nested in params)
                inner = new_config["data"]
                # For login: data.params.quInfo
                if "params" in inner and "quInfo" in inner.get("params", {}):
                    inner["params"]["quInfo"]["complexSliderRet"] = 0
                    inner["params"]["quInfo"]["complexSliderType"] = "clickImg"
                # For other APIs: data.data
                if "data" in inner and isinstance(inner["data"], dict):
                    inner["data"]["complexSliderRet"] = 0
                    inner["data"]["complexSliderType"] = "clickImg"
                # Also set at top data level
                inner["complexSliderRet"] = 0
                inner["complexSliderType"] = "clickImg"
            await asyncio.sleep(2)
            return await self._sgcc_request(new_config, retry_count=retry_count + 1, max_captcha_retries=max_captcha_retries)

        return result

    def _is_credential_expired(self, data: dict[str, Any]) -> bool:
        """Check if response indicates expired credentials."""
        code = data.get("code")
        if code is not None and int(code) in EXPIRED_CODES:
            return True
        # Special combos
        if code is not None and int(code) == 10004:
            msg = str(data.get("message", ""))
            if msg in ("请求异常【GC117】", "请求异常【010011】"):
                return True
        if code is not None and int(code) == 10002:
            msg = str(data.get("message", ""))
            if msg in ("WEB渠道KeyCode已失效", "Token 为空！"):
                return True
        # Keyword check
        msg = str(data.get("message", data))
        return any(kw in msg for kw in EXPIRED_KEYWORDS)

    async def _authenticated_request(
        self, config: dict[str, Any], retry_on_auth: bool = True
    ) -> dict[str, Any]:
        """Make an SGCC request with auto-re-login on credential expiry.
        
        Delegates to _sgcc_request for the encrypt→SGCC→decrypt cycle,
        which already handles captcha retries.
        """
        try:
            return await self._sgcc_request(config)
        except SgccAuthError:
            if retry_on_auth and self._username:
                self._log("凭证失效，自动重新登录...")
                await self._full_login(self._username, self._password)
                # Update config with fresh tokens
                hdrs = config.get("headers", {})
                hdrs["token"] = self._state.token
                hdrs["acctoken"] = self._state.access_token
                hdrs["keyCode"] = self._state.key_code
                hdrs["publicKey"] = self._state.public_key
                config["headers"] = hdrs
                return await self._authenticated_request(config, retry_on_auth=False)
            raise

    # ── Auth flow ─────────────────────────────────────────────────
    async def _full_login(self, username: str, password: str) -> None:
        """Complete login flow: risk → keyCode → login → authorize → webToken."""
        await self._get_risk_context()

        # Step 1: keyCode
        self._log("步骤1: 获取keyCode...")
        key_code_data = await self._sgcc_request({
            "url": API["keyCode"],
            "method": "post",
            "headers": {},
        })
        self._log(f"keyCode获取成功 ✓")

        # Step 2: Login
        self._log("步骤2: 登录...")
        login_result = await self._sgcc_request({
            "url": API["login"],
            "method": "post",
            "headers": {
                "keyCode": key_code_data["keyCode"],
                "publicKey": key_code_data["publicKey"],
            },
            "data": {
                "params": {
                    "uscInfo": {
                        "devciceIp": "",
                        "tenant": "state_grid",
                        "member": "0902",
                        "devciceId": "",
                    },
                    "quInfo": {
                        "optSys": "android",
                        "pushId": "000000",
                        "addressProvince": "110100",
                        "password": password,
                        "addressRegion": "110101",
                        "account": username,
                        "addressCity": "330100",
                    },
                }
            },
        })
        bizrt = login_result.get("bizrt", {})
        if not bizrt or not bizrt.get("userInfo"):
            raise SgccError(f"登录失败: {json.dumps(login_result, ensure_ascii=False)[:200]}")
        user_info = bizrt["userInfo"][0]
        token = bizrt["token"]
        self._log(f"登录成功 ✓ (用户: {user_info.get('realName', '?')})")

        # Step 3: Authorize code
        self._log("步骤3: 获取授权码...")
        auth_result = await self._sgcc_request({
            "url": API["authorize"],
            "method": "post",
            "headers": {
                "keyCode": key_code_data["keyCode"],
                "publicKey": key_code_data["publicKey"],
                "token": token,
            },
        })
        redirect = auth_result.get("redirect_url") or auth_result.get("redirectUrl") or ""
        import re
        from urllib.parse import unquote as _url_unquote
        m = re.search(r"[?&]code=([^&]+)", redirect)
        auth_code = m.group(1) if m else auth_result.get("code") or auth_result.get("authorizeCode")
        if auth_code:
            auth_code = _url_unquote(auth_code)
        self._log(f"授权码获取成功 ✓")

        # Step 4: WebToken
        self._log("步骤4: 获取WebToken...")
        web_token_result = await self._sgcc_request({
            "url": API["webToken"],
            "method": "post",
            "headers": {
                "keyCode": key_code_data["keyCode"],
                "publicKey": key_code_data["publicKey"],
                "token": token,
                "authorizecode": auth_code,
            },
        })
        access_token = web_token_result.get("access_token", "")
        if not access_token:
            raise SgccError(f"获取Token失败: {json.dumps(web_token_result, ensure_ascii=False)[:200]}")
        self._log("WebToken获取成功 ✓")

        # Save state
        self._state = LoginState(
            bizrt=bizrt,
            access_token=access_token,
            key_code_data=key_code_data,
            user_info=user_info,
        )
        self._username = username
        self._password = password

    async def login(self, username: str, password: str) -> list[dict[str, Any]]:
        """Login and return list of bound households (powerUserList)."""
        self._username = username
        self._password = password
        await self._full_login(username, password)

        # Step 5: Get bound info + household list
        self._log("步骤5: 获取绑定户号...")
        state = self._state
        bind_info = await self._authenticated_request({
            "url": API["bindInfo"],
            "method": "post",
            "headers": {
                "keyCode": state.key_code,
                "publicKey": state.public_key,
                "token": state.token,
                "acctoken": state.access_token,
            },
            "data": {
                "serviceCode": "0101183",
                "source": "SGAPP",
                "target": "32101",
                "uscInfo": {"member": "0902", "devciceIp": "", "devciceId": "", "tenant": "state_grid"},
                "quInfo": {"userId": state.user_id},
                "token": state.token,
                "Channels": "web",
            },
        })

        user_info_data = bind_info.get("bizrt", bind_info)
        user_list = user_info_data.get("powerUserList", [])
        if not user_list:
            raise SgccError("未查询到绑定户号")

        self._log(f"找到 {len(user_list)} 个户号:")
        for u in user_list:
            self._log(f"  - {u.get('consNo_dst', '?')} {u.get('consName_dst', '')}")
            # Map decrypted fields back for consistency
            u.setdefault("consName", u.get("consName_dst", ""))
            u.setdefault("elecAddr", u.get("elecAddr_dst", ""))

        self._households = user_list
        return user_list

    # ── Data fetch ────────────────────────────────────────────────
    async def _get_balance(
        self, cons_no_real: str, cons_no_enc: str, pro_code: str,
        org_no: str, cons_type: str,
    ) -> dict[str, Any]:
        """Get account balance for one household."""
        state = self._state
        result = await self._authenticated_request({
            "url": API["balance"],
            "method": "post",
            "headers": {
                "keyCode": state.key_code,
                "publicKey": state.public_key,
                "token": state.token,
                "acctoken": state.access_token,
            },
            "data": {
                "data": {
                    "srvCode": "",
                    "serialNo": "",
                    "channelCode": "0902",
                    "funcCode": "WEBA1007200",
                    "acctId": state.user_id,
                    "userName": state.user_name,
                    "promotType": "1",
                    "promotCode": "1",
                    "userAccountId": state.user_id,
                    "list": [{
                        "consNoSrc": cons_no_real,
                        "proCode": pro_code,
                        "sceneType": cons_type or "",
                        "consNo": cons_no_enc,
                        "orgNo": org_no,
                    }],
                },
                "serviceCode": "0101143",
                "source": "SGAPP",
                "target": pro_code,
            },
        })
        return result.get("list", [{}])[0] if isinstance(result.get("list"), list) else result

    async def _get_daily_usage(
        self, cons_no_real: str, pro_code: str, org_no: str, cons_type: str,
    ) -> dict[str, Any]:
        """Get last ~10 days of electricity usage."""
        state = self._state
        today = date.today()
        end_d = today - timedelta(days=1)
        start_d = today - timedelta(days=10)

        def fmt(d: date) -> str:
            return d.strftime("%Y-%m-%d")

        result = await self._authenticated_request({
            "url": API["usage"],
            "method": "post",
            "headers": {
                "keyCode": state.key_code,
                "publicKey": state.public_key,
                "token": state.token,
                "acctoken": state.access_token,
            },
            "data": {
                "params1": {
                    "serviceCode": "0101183",
                    "source": "SGAPP",
                    "target": "32101",
                    "uscInfo": {"member": "0902", "devciceIp": "", "devciceId": "", "tenant": "state_grid"},
                    "quInfo": {"userId": state.user_id},
                    "token": state.token,
                },
                "params3": {
                    "data": {
                        "acctId": state.user_id,
                        "consNo": cons_no_real,
                        "consType": "02" if str(cons_type) == "02" else "01",
                        "endTime": fmt(end_d),
                        "orgNo": org_no,
                        "queryYear": str(today.year),
                        "proCode": pro_code,
                        "provinceCode": pro_code,
                        "serialNo": "",
                        "srvCode": "",
                        "startTime": fmt(start_d),
                        "userName": state.user_name,
                        "funcCode": "WEBALIPAY_01",
                        "channelCode": "0902",
                        "clearCache": "11",
                        "promotCode": "1",
                        "promotType": "1",
                    },
                    "serviceCode": "BCP_000026",
                    "source": "app",
                    "target": pro_code,
                },
                "params4": "010103",
            },
        })
        return result

    async def _get_monthly_usage(
        self, cons_no_real: str, pro_code: str, org_no: str, cons_type: str,
    ) -> dict[str, Any]:
        """Get monthly electricity usage for current year."""
        state = self._state
        result = await self._authenticated_request({
            "url": API["usage"],
            "method": "post",
            "headers": {
                "keyCode": state.key_code,
                "publicKey": state.public_key,
                "token": state.token,
                "acctoken": state.access_token,
            },
            "data": {
                "params1": {
                    "serviceCode": "0101183",
                    "source": "SGAPP",
                    "target": "32101",
                    "uscInfo": {"member": "0902", "devciceIp": "", "devciceId": "", "tenant": "state_grid"},
                    "quInfo": {"userId": state.user_id},
                    "token": state.token,
                },
                "params3": {
                    "data": {
                        "acctId": state.user_id,
                        "consNo": cons_no_real,
                        "consType": cons_type or "01",
                        "orgNo": org_no,
                        "proCode": pro_code,
                        "provinceCode": pro_code,
                        "queryYear": str(date.today().year),
                        "serialNo": "",
                        "srvCode": "",
                        "userName": state.user_name,
                        "funcCode": "WEBALIPAY_01",
                        "channelCode": "0902",
                        "clearCache": "09",
                        "promotType": "1",
                    },
                    "serviceCode": "BCP_000026",
                    "source": "app",
                    "target": pro_code,
                },
                "params4": "010102",
            },
        })
        return result

    # ── Public API ────────────────────────────────────────────────
    async def fetch_all(self) -> list[dict[str, Any]]:
        """Fetch data for all bound households.

        Returns list of dicts matching the QingLong MQTT payload format,
        ready to feed into _process_qinglong_data().
        """
        state = self._state
        user_list = getattr(self, "_households", None) or []

        results = []
        for user in user_list:
            cons_no_real = user.get("consNo_dst") or user.get("consNo", "")
            cons_no_enc = user.get("consNo") or user.get("consNo_dst", "")
            pro_code = user.get("proNo") or user.get("provinceId") or "32101"
            org_no = user.get("orgNo") or user.get("orgNo_dst") or ""
            cons_type = user.get("constType") or user.get("consType") or "01"
            cons_name = user.get("consName_dst") or user.get("consName") or ""
            address = user.get("elecAddr_dst") or user.get("elecAddr") or ""
            org_name = user.get("orgName", "")

            self._log(f"\n查询户号: {cons_no_real} ({cons_name})")

            balance = await self._get_balance(cons_no_real, cons_no_enc, pro_code, org_no, cons_type)
            daily = await self._get_daily_usage(cons_no_real, pro_code, org_no, cons_type)
            monthly = await self._get_monthly_usage(cons_no_real, pro_code, org_no, cons_type)

            # Format to match QingLong MQTT payload
            def _fmt_date(s: str) -> str:
                s = str(s)
                if len(s) == 8:
                    return f"{s[:4]}-{s[4:6]}-{s[6:]}"
                if len(s) == 6:
                    return f"{s[:4]}-{s[4:]}"
                return s

            # The daily usage response structure: sevenEleList (last 7 days)
            seven_list = daily.get("sevenEleList", [])
            day_list = [
                {
                    "day": _fmt_date(item["day"]),
                    "dayElePq": item.get("dayElePq", "0"),
                    "thisVPq": item.get("thisVPq", "0"),
                    "thisPPq": item.get("thisPPq", "0"),
                    "thisNPq": item.get("thisNPq", "0"),
                    "thisTPq": item.get("thisTPq", "0"),
                }
                for item in seven_list
                if item.get("dayElePq") != "-"
            ]

            # Monthly usage: mothEleList
            moth_list = monthly.get("mothEleList", [])
            month_list = [
                {
                    "month": _fmt_date(item["month"]),
                    "monthEleNum": item.get("monthEleNum", 0),
                    "monthEleCost": item.get("monthEleCost", 0),
                }
                for item in moth_list
            ]

            data_info = monthly.get("dataInfo", {})
            total_ele_num = data_info.get("totalEleNum", 0)
            total_ele_cost = data_info.get("totalEleCost", 0)

            # Build payload matching the QingLong script's sendMqtt format
            payload = {
                "sumMoney": balance.get("sumMoney", balance.get("balance", 0)),
                "date": date.today().strftime("%Y-%m-%d"),
                "dayList": day_list,
                "monthList": month_list,
                "totalEleNum": str(total_ele_num),
                "totalEleCost": str(total_ele_cost),
            }

            results.append({
                "consNo": cons_no_real,
                "consName": cons_name,
                "address": address,
                "orgName": org_name,
                "data": payload,
            })

        return results


# ── Standalone test ──────────────────────────────────────────────────
async def main() -> None:
    """Quick test: login and fetch data."""
    import os
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    username = os.environ.get("SGCC_USERNAME", "")
    password = os.environ.get("SGCC_PASSWORD", "")

    if not username or not password:
        print("请设置环境变量: SGCC_USERNAME, SGCC_PASSWORD")
        return

    async with SgccClient(debug=True) as client:
        try:
            households = await client.login(username, password)
            print(f"\n共 {len(households)} 个户号")

            results = await client.fetch_all()
            for r in results:
                print(f"\n{'='*50}")
                print(f"户号: {r['consNo']}")
                print(f"户名: {r['consName']}")
                print(f"地址: {r['address']}")
                d = r["data"]
                print(f"余额: {d['sumMoney']} 元")
                print(f"本年累计电量: {d['totalEleNum']} kWh")
                print(f"本年累计电费: {d['totalEleCost']} 元")
                print(f"日数据: {len(d['dayList'])} 条")
                print(f"月数据: {len(d['monthList'])} 条")
                if d["dayList"]:
                    latest = d["dayList"][-1]
                    print(f"  最新日: {latest['day']} 用电 {latest.get('dayElePq', 0)} kWh")

        except SgccError as e:
            print(f"\n错误: {e}")


if __name__ == "__main__":
    asyncio.run(main())
