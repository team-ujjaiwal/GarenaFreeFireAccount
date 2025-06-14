import asyncio
import time
import httpx
import json
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB49"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}
DEFAULT_MAP_CODE = "FFBR"  # Default map code for Bermuda

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=3959788424&password=513E781858206A2994D10F7E767C4F1567549C7A4343488663B6EBC9A0880E31"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=uid&password=password"
    else:
        return "uid=uid&password=password"

# === Token Generation ===
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)
    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    })
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))  # Fixed line
        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200
        }

async def initialize_tokens():
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)  # Refresh every 7 hours
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def get_map_data(server: str, headers: dict):
    try:
        map_request = AccountPersonalShow_pb2.MapRequest()
        map_request.map_code = DEFAULT_MAP_CODE
        map_payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, map_request.SerializeToString())
        
        async with httpx.AsyncClient() as client:
            map_resp, craftland_resp = await asyncio.gather(
                client.post(server + "/GetMapInfo", data=map_payload, headers=headers),
                client.post(server + "/GetCraftlandInfo", data=map_payload, headers=headers)
            )
            
            map_info = AccountPersonalShow_pb2.MapInfo()
            map_info.ParseFromString(map_resp.content)
            
            craftland_info = AccountPersonalShow_pb2.CraftlandInfo()
            craftland_info.ParseFromString(craftland_resp.content)
            
            return {
                "map_info": json_format.MessageToDict(map_info),
                "craftland_info": json_format.MessageToDict(craftland_info)
            }
    except Exception as e:
        return {"error": f"Failed to fetch map data: {str(e)}"}

async def GetAccountInformation(uid: str, region: str):
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")
    
    token, lock, server = await get_token_info(region)
    
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    
    async with httpx.AsyncClient() as client:
        # Get player info
        player_payload = await json_to_proto(
            json.dumps({'a': uid, 'b': "7"}),  # "7" is the default unk value
            main_pb2.GetPlayerPersonalShow()
        )
        player_data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, player_payload)
        player_resp = await client.post(
            server + "/GetPlayerPersonalShow",
            data=player_data_enc,
            headers=headers
        )
        player_data = json.loads(json_format.MessageToJson(
            decode_protobuf(player_resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo())
        ))
        
        # Get map data in parallel
        map_data = await get_map_data(server, headers)
        
        return {
            "status": "success",
            "data": {
                "player_info": player_data,
                "map_data": map_data
            },
            "timestamp": int(time.time())
        }

# === Caching Decorator ===
def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = (request.path, tuple(sorted(request.args.items())))
            if key in cache:
                return cache[key]
            res = fn(*args, **kwargs)
            cache[key] = res
            return res
        return wrapper
    return decorator

# === Flask Routes ===
@app.route('/player-info', methods=['GET'])
@cached_endpoint(ttl=600)  # Cache for 10 minutes
def get_account_info():
    region = request.args.get('region')
    uid = request.args.get('uid')

    if not uid:
        return jsonify({"status": "error", "message": "UID parameter is required"}), 400
    if not region:
        return jsonify({"status": "error", "message": "Region parameter is required"}), 400

    try:
        result = asyncio.run(GetAccountInformation(uid, region))
        return jsonify(result), 200
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Internal server error: {str(e)}"}), 500

@app.route('/refresh-tokens', methods=['POST'])
def refresh_tokens():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({"status": "success", "message": "Tokens refreshed successfully"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# === Startup ===
async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup())
    app.run(host='0.0.0.0', port=5000, debug=True)