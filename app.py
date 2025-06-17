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
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

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
        return "uid=3959796107&password=642AECAE83EA5A3578B4FD40FF56FA281D33F0DAFE1A25B90A01595BE501E4D2"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=3978687748&password=9C22CD3ED0E9781167583B815F53EB36AB9C560098324EF8DCD514B61A4146D7"
    else:
        return "uid=3978690138&password=DB98F58E07C248FAA82CB7FD4527DC37607CFF6C2DC48D1788F52238FFF4DA83"

# === Token Generation ===
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1",
               'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
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
        await asyncio.sleep(25200)
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str,str,str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue",
               'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
               'ReleaseVersion': RELEASEVERSION}
    async with httpx.AsyncClient() as client:
        resp = await client.post(server+endpoint, data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

# === Caching Decorator ===
def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

# === Flask Routes ===
@app.route('/data-fetch')
@cached_endpoint()
def get_account_info():
    region = request.args.get('region')
    uid = request.args.get('uid')

    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    if not region:
        return jsonify({"error": "Please provide REGION."}), 400

    try:
        raw_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
        
        transformed_data = {
    "AccountInfo": {
        "AccountAvatarId": raw_data["basicInfo"].get("headPic", 0),
        "AccountBPBadges": raw_data["basicInfo"].get("badgeCnt", 0),
        "AccountBPID": raw_data["basicInfo"].get("badgeId", 0),
        "AccountBannerId": raw_data["basicInfo"].get("bannerId", 0),
        "AccountCreateTime": raw_data["basicInfo"].get("createAt", 0),
        "AccountEXP": raw_data["basicInfo"].get("exp", 0),
        "AccountLastLogin": raw_data["basicInfo"].get("lastLoginAt", 0),
        "AccountLevel": raw_data["basicInfo"].get("level", 0),
        "AccountLikes": raw_data["basicInfo"].get("liked", 0),
        "AccountName": raw_data["basicInfo"].get("nickname", ""),
        "AccountRegion": raw_data["basicInfo"].get("region", ""),
        "AccountSeasonId": raw_data["basicInfo"].get("seasonId", 0),
        "AccountType": raw_data["basicInfo"].get("accountType", 0),
        "AvatarImage": f"https://www.dl.cdn.freefireofficial.com/icons/{raw_data['basicInfo'].get('headPic', 0)}.png",
        "BannerImage": f"https://www.dl.cdn.freefireofficial.com/icons/{raw_data['basicInfo'].get('bannerId', 0)}.png",
        "BrMaxRank": raw_data["basicInfo"].get("maxRank", 0),
        "BrRankPoint": raw_data["basicInfo"].get("rankingPoints", 0),
        "CsMaxRank": raw_data["basicInfo"].get("csMaxRank", 0),
        "CsRankPoint": raw_data["basicInfo"].get("csRankingPoints", 0),
        "EquippedWeapon": raw_data["basicInfo"].get("weaponSkinShows", []),
        "EquippedWeaponImages": [
            f"https://www.dl.cdn.freefireofficial.com/icons/{weapon}.png" 
            for weapon in raw_data["basicInfo"].get("weaponSkinShows", [])
        ],
        "ReleaseVersion": raw_data["basicInfo"].get("releaseVersion", ""),
        "Role": raw_data["basicInfo"].get("role", 0),
        "ShowBrRank": raw_data["basicInfo"].get("showBrRank", False),
        "ShowCsRank": raw_data["basicInfo"].get("showCsRank", False),
        "Title": raw_data["basicInfo"].get("title", 0),
        "hasElitePass": raw_data["basicInfo"].get("hasElitePass", False) or 
                       any(str(item).startswith('9') for item in raw_data["profileInfo"].get("equipedItems", []))
    },
    "AccountProfileInfo": {
        "EquippedOutfit": raw_data["profileInfo"].get("clothes", []),
        "EquippedOutfitImages": [
            f"https://www.dl.cdn.freefireofficial.com/icons/{item}.png" 
            for item in raw_data["profileInfo"].get("clothes", [])
        ],
        "EquippedSkills": raw_data["profileInfo"].get("equipedSkills", [])
    },
    "GuildInfo": {
        "GuildCapacity": raw_data["clanBasicInfo"].get("capacity", 0),
        "GuildID": raw_data["clanBasicInfo"].get("clanId", ""),
        "GuildLevel": raw_data["clanBasicInfo"].get("clanLevel", 0),
        "GuildMember": raw_data["clanBasicInfo"].get("memberNum", 0),
        "GuildName": raw_data["clanBasicInfo"].get("clanName", ""),
        "GuildOwner": raw_data["clanBasicInfo"].get("captainId", "")
    },
    "captainBasicInfo": {
        "EquippedWeapon": raw_data["basicInfo"].get("weaponSkinShows", []),
        "accountId": raw_data["basicInfo"].get("accountId", ""),
        "accountType": raw_data["basicInfo"].get("accountType", 0),
        "badgeCnt": raw_data["basicInfo"].get("badgeCnt", 0),
        "badgeId": raw_data["basicInfo"].get("badgeId", 0),
        "bannerId": raw_data["basicInfo"].get("bannerId", 0),
        "createAt": raw_data["basicInfo"].get("createAt", 0),
        "csMaxRank": raw_data["basicInfo"].get("csMaxRank", 0),
        "csRank": raw_data["basicInfo"].get("csRank", 0),
        "csRankingPoints": raw_data["basicInfo"].get("csRankingPoints", 0),
        "exp": raw_data["basicInfo"].get("exp", 0),
        "headPic": raw_data["basicInfo"].get("headPic", 0),
        "lastLoginAt": raw_data["basicInfo"].get("lastLoginAt", 0),
        "level": raw_data["basicInfo"].get("level", 0),
        "liked": raw_data["basicInfo"].get("liked", 0),
        "maxRank": raw_data["basicInfo"].get("maxRank", 0),
        "nickname": raw_data["basicInfo"].get("nickname", ""),
        "rank": raw_data["basicInfo"].get("rank", 0),
        "rankingPoints": raw_data["basicInfo"].get("rankingPoints", 0),
        "region": raw_data["basicInfo"].get("region", ""),
        "releaseVersion": raw_data["basicInfo"].get("releaseVersion", ""),
        "seasonId": raw_data["basicInfo"].get("seasonId", 0),
        "showBrRank": raw_data["basicInfo"].get("showBrRank", False),
        "showCsRank": raw_data["basicInfo"].get("showCsRank", False),
        "title": raw_data["basicInfo"].get("title", 0)
    },
    "creditScoreInfo": {
        "creditScore": raw_data["creditScoreInfo"].get("creditScore", 0),
        "periodicSummaryEndTime": raw_data["creditScoreInfo"].get("periodicSummaryEndTime", 0),
        "rewardState": 1 if raw_data["creditScoreInfo"].get("rewardState", "") == "REWARD_STATE_UNCLAIMED" else 0
    },
    "petInfo": {
        "exp": raw_data["petInfo"].get("exp", 0),
        "id": raw_data["petInfo"].get("id", 0),
        "isSelected": raw_data["petInfo"].get("isSelected", False),
        "level": raw_data["petInfo"].get("level", 0),
        "name": raw_data["petInfo"].get("name", ""),
        "selectedSkillId": raw_data["petInfo"].get("selectedSkillId", 0),
        "skinId": raw_data["petInfo"].get("skinId", 0)
    },
    "socialinfo": {
        "AccountLanguage": raw_data["socialInfo"].get("language", "").replace("Language_", ""),
        "AccountPreferMode": raw_data["socialInfo"].get("modePrefer", "").replace("ModePrefer_", ""),
        "AccountSignature": raw_data["socialInfo"].get("signature", "")
    }
}

        return jsonify(transformed_data)

    except Exception as e:
        return jsonify({"error": "Invalid UID or Region. Please check and try again.", "details": str(e)}), 500

@app.route('/refresh', methods=['GET','POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message':'Tokens refreshed for all regions.'}),200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}),500

# === Startup ===
async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    asyncio.run(startup())
    app.run(host='0.0.0.0', port=5000, debug=True)
