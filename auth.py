# Based on https://github.com/liusida/ComfyUI-Login
# Special thanks to @liusida

import server
from comfy.cli_args import args
from aiohttp import web
import base64
import os
import logging
import json

node_dir = os.path.dirname(__file__)
required_group = os.getenv("REQUIRED_GROUP", "membership")
redirect_url = os.getenv("REDIRECT_URL", "https://example.com/membership")

# Access the PromptServer instance and its app
prompt_server = server.PromptServer.instance
app = prompt_server.app
routes = prompt_server.routes

async def process_request(request, handler):
    """Process the request by calling the handler and setting response headers."""
    response = await handler(request)
    if request.path == '/':  # Prevent caching the main page after logout
        response.headers.setdefault('Cache-Control', 'no-cache')
    return response

@web.middleware
async def check_login_status(request: web.Request, handler):
    # 静的ファイルはスキップ
    if request.path.endswith(('.css', '.css.map', '.js', '.ico')):
        return await handler(request)

    # ALBのOIDCヘッダーを取得
    oidc_header = request.headers.get('x-amzn-oidc-data')
    if not oidc_header:
        return unauthorized_response(request)

    try:
        # ヘッダーをデコードしてJWTを検証
        decoded_token = decode_verify_jwt(oidc_header)
        
        # cognito:groupsの確認
        cognito_groups = decoded_token.get('cognito:groups', [])
        if required_group not in cognito_groups:
            return membership_required_response()

        # 認証OK
        return await process_request(request, handler)

    except Exception as e:
        logging.error(f"Authentication error: {str(e)}")
        return unauthorized_response(request)

def decode_verify_jwt(token):
    # JWTのデコード処理
    # 注: 実際の実装では適切な検証が必要です
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    
    payload = parts[1]
    padding = '=' * (4 - len(payload) % 4)
    decoded_payload = base64.urlsafe_b64decode(payload + padding)
    return json.loads(decoded_payload)

def unauthorized_response(request):
    accept_header = request.headers.get('Accept', '')
    if 'text/html' in accept_header:
        raise web.HTTPFound(redirect_url)
    else:
        return web.json_response({
            'error': 'Authentication required'
        }, status=401)

def membership_required_response():
    raise web.HTTPFound(redirect_url)

app.middlewares.append(check_login_status)

old_css_path = os.path.join(node_dir, "old_css")
app.router.add_static('/old_css/', old_css_path)

NODE_CLASS_MAPPINGS = {}
