# Based on https://github.com/liusida/ComfyUI-Login
# Special thanks to @liusida

import server
from comfy.cli_args import args
from aiohttp import web
import base64
import os
import logging
import json
import jwt
import requests
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

node_dir = os.path.dirname(__file__)
required_groups = [group.strip() for group in os.getenv("REQUIRED_GROUP", "membership").split(',')]
logging.info(f"REQUIRED_GROUP from env: {required_groups}")
redirect_url = os.getenv("REDIRECT_URL", "https://example.com/membership")
logging.info(f"REDIRECT_URL from env: {redirect_url}")

# Get setting from environment variables
region = os.getenv('AWS_REGION', 'ap-northeast-1')
logging.info(f"AWS_REGION from env: {region}")
user_pool_id = os.getenv('COGNITO_USER_POOL_ID')
logging.info(f"COGNITO_USER_POOL_ID from env: {user_pool_id}")
client_id = os.getenv('COGNITO_CLIENT_ID')
logging.info(f"COGNITO_CLIENT_ID from env: {client_id}")

if not user_pool_id or not client_id:
    raise ValueError("COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID must be set")

# Build JWKS URL
issuer = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}'
jwks_url = f'{issuer}/.well-known/jwks.json'

# Get signing key
jwks_client = jwt.PyJWKClient(jwks_url)

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
    # Health check path
    if request.path == '/system_stats':
        return await handler(request)

    # Static files are skipped
    if request.path.endswith(('.css', '.css.map', '.js', '.ico')):
        return await handler(request)

    # Access Token ヘッダーを取得
    access_token = request.headers.get('x-amzn-oidc-accesstoken')
    if not access_token:
        # return unauthorized_response(request)
        return await process_request(request, handler)

    try:
        # Decode header and verify JWT
        decoded_token = decode_verify_jwt(access_token)

        # Check cognito:groups
        cognito_groups = decoded_token.get('cognito:groups', [])
        # Check if any of the user's groups are in the required groups
        if not any(group in required_groups for group in cognito_groups):
            # return membership_required_response()
            return await process_request(request, handler)

        # Authentication OK
        return await process_request(request, handler)

    except Exception as e:
        logging.error(f"Authentication error: {str(e)}")
        # return unauthorized_response(request)
        return await process_request(request, handler)

def decode_verify_jwt(token):
    """Decode and verify the Cognito access token."""
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Decode the token
        decoded_token = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=client_id,
            issuer=issuer,
            options={
                "verify_aud": False,  # Cognito Access Token does not contain aud claim
                "verify_exp": True,  # Verify expiration
                "verify_iat": True,  # Verify issued at
                "verify_nbf": True,  # Verify not before
            }
        )

        # Check if it is an access token
        if decoded_token.get('token_use') != 'access':
            raise ValueError("Invalid token_use - expected 'access'")

        return decoded_token

    except jwt.ExpiredSignatureError:
        logging.error("Token has expired")
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError as e:
        logging.error(f"Invalid token: {str(e)}")
        raise ValueError(f"Invalid token: {str(e)}")
    except Exception as e:
        logging.error(f"JWT verification failed: {str(e)}")
        raise ValueError(f"Token verification failed: {str(e)}")

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

NODE_CLASS_MAPPINGS = {}
