import asyncio
import time
import httpx
import json
import logging
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB49"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}
DEFAULT_MAP_CODE = "FFBR"  # Default map code

app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# Helper Functions
def pad(text: bytes) -> bytes:
    return text + (AES.block_size - len(text) % AES.block_size * chr(AES.block_size - len(text) % AES.block_size).encode()

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type) -> Message:
    msg = message_type()
    msg.ParseFromString(encoded_data)
    return msg

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.Parse(json_data, proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=3959788424&password=513E781858206A2994D10F7E767C4F1567549C7A4343488663B6EBC9A0880E31"
    return "uid=uid&password=password"

# Token Management
async def get_access_token(account: str) -> Tuple[str, str]:
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"{account}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", ""), data.get("open_id", "")

async def create_jwt(region: str):
    try:
        account = get_account_credentials(region)
        token_val, open_id = await get_access_token(account)
        
        login_req = {
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4"
        }
        
        # Initialize protobuf message correctly
        from proto import FreeFire_pb2
        login_request = FreeFire_pb2.LoginReq()
        json_format.ParseDict(login_req, login_request)
        
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, login_request.SerializeToString())
        
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            'User-Agent': USERAGENT,
            'Content-Type': "application/octet-stream",
            'X-Unity-Version': "2018.4.11f1",
            'ReleaseVersion': RELEASEVERSION
        }
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, data=payload, headers=headers)
            
            # Correct protobuf decoding
            from proto import FreeFire_pb2
            login_res = FreeFire_pb2.LoginRes()
            login_res.ParseFromString(resp.content)
            
            msg = json_format.MessageToDict(login_res)
            cached_tokens[region] = {
                'token': f"Bearer {msg.get('token', '')}",
                'server_url': msg.get('serverUrl', ''),
                'expires_at': time.time() + 25200
            }
            
    except Exception as e:
        logger.error(f"JWT creation failed: {str(e)}")
        raise

async def initialize_tokens():
    await asyncio.gather(*[create_jwt(r) for r in SUPPORTED_REGIONS])

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str, str]:
    region = region.upper()
    if region not in cached_tokens or time.time() > cached_tokens[region]['expires_at']:
        await create_jwt(region)
    return cached_tokens[region]['token'], cached_tokens[region]['server_url']

# Data Fetching
async def fetch_player_data(uid: str, server: str, headers: dict):
    from proto import main_pb2, AccountPersonalShow_pb2
    
    player_req = main_pb2.GetPlayerPersonalShow()
    player_req.a = uid
    player_req.b = "7"  # Default value
    
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, player_req.SerializeToString())
    
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{server}/GetPlayerPersonalShow",
            data=payload,
            headers=headers
        )
        
        player_info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
        player_info.ParseFromString(resp.content)
        return json_format.MessageToDict(player_info)

async def fetch_map_data(server: str, headers: dict):
    from proto import AccountPersonalShow_pb2
    
    map_req = AccountPersonalShow_pb2.MapRequest()
    map_req.map_code = DEFAULT_MAP_CODE
    
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, map_req.SerializeToString())
    
    async with httpx.AsyncClient() as client:
        map_resp, craftland_resp = await asyncio.gather(
            client.post(f"{server}/GetMapInfo", data=payload, headers=headers),
            client.post(f"{server}/GetCraftlandInfo", data=payload, headers=headers)
        )
        
        map_info = AccountPersonalShow_pb2.MapInfo()
        map_info.ParseFromString(map_resp.content)
        
        craftland_info = AccountPersonalShow_pb2.CraftlandInfo()
        craftland_info.ParseFromString(craftland_resp.content)
        
        return {
            "map_info": json_format.MessageToDict(map_info),
            "craftland_info": json_format.MessageToDict(craftland_info)
        }

async def get_account_data(uid: str, region: str):
    try:
        token, server = await get_token_info(region)
        
        headers = {
            'User-Agent': USERAGENT,
            'Content-Type': "application/octet-stream",
            'Authorization': token,
            'X-Unity-Version': "2018.4.11f1",
            'ReleaseVersion': RELEASEVERSION
        }
        
        player_data, map_data = await asyncio.gather(
            fetch_player_data(uid, server, headers),
            fetch_map_data(server, headers)
        )
        
        return {
            "status": "success",
            "data": {
                "player_info": player_data,
                "map_data": map_data
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get account data: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }

# Flask Endpoints
@app.route('/player-info', methods=['GET'])
def player_info():
    uid = request.args.get('uid')
    region = request.args.get('region')
    
    if not uid or not region:
        return jsonify({"status": "error", "message": "UID and Region are required"}), 400
    
    try:
        result = asyncio.run(get_account_data(uid, region))
        return jsonify(result), 200 if result["status"] == "success" else 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Startup
async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup())
    app.run(host='0.0.0.0', port=5000)