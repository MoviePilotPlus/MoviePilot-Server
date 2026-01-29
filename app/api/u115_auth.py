"""
115网盘 OAuth2授权 API路由
"""

import time
import secrets
from typing import Dict
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, JSONResponse

from app.core.config import settings

router = APIRouter()

# Key: state, Value: AuthSession
auth_sessions: Dict[str, dict] = {}


class AuthSession:
    """
    授权会话
    """

    def __init__(self, state: str):
        self.state = state
        self.status = "pending"
        self.access_token = None
        self.refresh_token = None
        self.expires_in = None
        self.created_at = time.time()
        self.expires_at = time.time() + 300

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "status": self.status,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_in": self.expires_in,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


def cleanup_expired_sessions():
    """
    清理过期的会话
    """
    current_time = time.time()
    expired_states = [
        state
        for state, session in auth_sessions.items()
        if session["expires_at"] < current_time
    ]
    for state in expired_states:
        del auth_sessions[state]


@router.get("/auth_url")
def get_auth_url():
    """
    生成115授权URL
    """
    if (
        not settings.U115_CLIENT_ID
        or not settings.U115_CLIENT_SECRET
        or not settings.U115_REDIRECT_URI
    ):
        return JSONResponse(
            content={
                "success": False,
                "message": "115网盘OAuth2配置不完整，请设置环境变量: U115_CLIENT_ID, U115_CLIENT_SECRET, U115_REDIRECT_URI",
            },
            status_code=500,
        )

    cleanup_expired_sessions()

    state = secrets.token_urlsafe(32)

    session = AuthSession(state)
    auth_sessions[state] = session.to_dict()

    params = {
        "client_id": settings.U115_CLIENT_ID,
        "redirect_uri": settings.U115_REDIRECT_URI,
        "response_type": "code",
        "state": state,
    }
    auth_url = f"https://passportapi.115.com/open/authorize?{urlencode(params)}"

    return JSONResponse(
        content={"success": True, "data": {"auth_url": auth_url, "state": state}}
    )


@router.get("/auth_callback")
async def auth_callback(
    code: str = Query(..., description="授权码"),
    state: str = Query(..., description="状态码"),
):
    """
    115 OAuth2回调接口
    """
    cleanup_expired_sessions()

    if state not in auth_sessions:
        return HTMLResponse(
            content=generate_error_page("授权会话不存在或已过期"), status_code=400
        )

    session = auth_sessions[state]
    if session["expires_at"] < time.time():
        return HTMLResponse(
            content=generate_error_page("授权会话已过期"), status_code=400
        )

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://passportapi.115.com/open/authCodeToToken",
                data={
                    "client_id": settings.U115_CLIENT_ID,
                    "client_secret": settings.U115_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": settings.U115_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10.0,
            )

            if resp.status_code != 200:
                return HTMLResponse(
                    content=generate_error_page(f"请求失败: HTTP {resp.status_code}"),
                    status_code=400,
                )

            result = resp.json()

            if result.get("state") != 1:
                error_msg = result.get("message", "获取token失败")
                return HTMLResponse(
                    content=generate_error_page(error_msg), status_code=400
                )

            data = result.get("data", {})
            session["status"] = "completed"
            session["access_token"] = data.get("access_token")
            session["refresh_token"] = data.get("refresh_token")
            session["expires_in"] = data.get("expires_in")
            auth_sessions[state] = session

            return HTMLResponse(content=generate_success_page())

    except httpx.RequestError as e:
        return HTMLResponse(
            content=generate_error_page(f"网络错误: {str(e)}"), status_code=500
        )
    except Exception as e:
        return HTMLResponse(
            content=generate_error_page(f"服务器错误: {str(e)}"), status_code=500
        )


@router.get("/token")
def get_token(state: str = Query(..., description="状态码")):
    """
    获取Token接口
    """
    cleanup_expired_sessions()

    if state not in auth_sessions:
        return JSONResponse(
            content={
                "success": False,
                "status": "expired",
                "message": "授权会话不存在或已过期",
            }
        )

    session = auth_sessions[state]

    if session["expires_at"] < time.time():
        del auth_sessions[state]
        return JSONResponse(
            content={"success": False, "status": "expired", "message": "授权会话已过期"}
        )

    if session["status"] == "completed":
        token_data = {
            "access_token": session["access_token"],
            "refresh_token": session["refresh_token"],
            "expires_in": session["expires_in"],
        }
        del auth_sessions[state]
        return JSONResponse(
            content={"success": True, "status": "completed", "data": token_data}
        )
    else:
        return JSONResponse(
            content={"success": False, "status": "pending", "message": "等待用户授权"}
        )


def generate_success_page() -> str:
    """
    生成授权成功页面
    """
    return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>115授权成功</title>
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 1rem;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 400px;
        }
        .success-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 1.5rem;
            background: #4caf50;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .success-icon::before {
            content: '✓';
            color: white;
            font-size: 3rem;
            font-weight: bold;
        }
        h1 {
            color: #333;
            margin: 0 0 0.5rem;
            font-size: 1.75rem;
        }
        p {
            color: #666;
            margin: 0 0 1.5rem;
            font-size: 1rem;
        }
        .close-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 0.75rem 2rem;
            border-radius: 0.5rem;
            font-size: 1rem;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .close-btn:hover {
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon"></div>
        <h1>授权成功</h1>
        <p>115网盘已成功授权，您可以关闭此窗口了</p>
        <button class="close-btn" onclick="window.close()">关闭窗口</button>
    </div>
    <script>
        // 3秒后自动关闭窗口
        setTimeout(() => {
            window.close();
        }, 3000);
    </script>
</body>
</html>
    """


def generate_error_page(error_message: str) -> str:
    """
    生成授权失败页面
    """
    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>115授权失败</title>
    <style>
        body {{
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}
        .container {{
            background: white;
            padding: 3rem;
            border-radius: 1rem;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 400px;
        }}
        .error-icon {{
            width: 80px;
            height: 80px;
            margin: 0 auto 1.5rem;
            background: #f44336;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .error-icon::before {{
            content: '✗';
            color: white;
            font-size: 3rem;
            font-weight: bold;
        }}
        h1 {{
            color: #333;
            margin: 0 0 0.5rem;
            font-size: 1.75rem;
        }}
        p {{
            color: #666;
            margin: 0 0 1.5rem;
            font-size: 1rem;
        }}
        .close-btn {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            border: none;
            padding: 0.75rem 2rem;
            border-radius: 0.5rem;
            font-size: 1rem;
            cursor: pointer;
            transition: transform 0.2s;
        }}
        .close-btn:hover {{
            transform: translateY(-2px);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon"></div>
        <h1>授权失败</h1>
        <p>{error_message}</p>
        <button class="close-btn" onclick="window.close()">关闭窗口</button>
    </div>
</body>
</html>
    """
