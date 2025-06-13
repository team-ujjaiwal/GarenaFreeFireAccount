# -*- coding: utf-8 -*-
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
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2, map_info_pb2
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

# Sample map data - replace with your actual data source
MAP_DATA = {
    "FREEFIREFEBB4B285F5A973E8975C8FECB32C2B84805": {
        "MapTitle": "8P_SUPER_CREATOR_MODE",
        "description": "[B][00FF00][C]YT - RUSHKEY\n[FFFF00]SUBSCRIBE [FFFFFF]AND SUPPORT US FOR MORE MAPS"
    },
    "DEFAULT": {
        "MapTitle": "DEFAULT_MAP",
        "description": "Default map description"
    }
}

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
        return "uid=3959788424&password=513E781858206A2994D10F7E767C4F1567549C7A4343488663B6EBC9A0880E31"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=uid&password=password"
    else:
        return "uid=uid&password=password"

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

async def GetMapInformation(map_code: str = "FREEFIREFEBB4B285F5A973E8975C8FECB32C2B84805"):
    # Create MapInfo protobuf message
    map_info = map_info_pb2.MapInfo()
    
    # Get data from our sample data (replace with your actual data source)
    map_data = MAP_DATA.get(map_code.upper(), MAP_DATA["DEFAULT"])
    
    # Set the protobuf fields
    map_info.MapCode = map_code
    map_info.MapTitle = map_data["MapTitle"]
    map_info.description = map_data["description"]
    
    # Convert to dictionary for JSON response
    return json_format.MessageToDict(map_info)

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
        proto_response = decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
        data = json_format.MessageToDict(proto_response)
        
        # Get map information
        map_info = await GetMapInformation()
        
        # Transform the data into your desired format
        response = [
            {
                "AccountInfo": {
                    "AccountAvatarId": data.get("profileInfo", {}).get("avatarId", 902048021),
                    "AccountBPBadges": data.get("basicInfo", {}).get("badgeCnt", 77),
                    "AccountBPID": data.get("basicInfo", {}).get("badgeId", 1001000085),
                    "AccountBannerId": data.get("basicInfo", {}).get("bannerId", 901049014),
                    "AccountCreateTime": data.get("basicInfo", {}).get("createAt", 1554369968),
                    "AccountEXP": data.get("basicInfo", {}).get("exp", 4819176),
                    "AccountId": data.get("basicInfo", {}).get("accountId", 868374805),
                    "AccountLastLogin": data.get("basicInfo", {}).get("lastLoginAt", 1749777499),
                    "AccountLevel": data.get("basicInfo", {}).get("level", 75),
                    "AccountLikes": data.get("basicInfo", {}).get("liked", 80695),
                    "AccountName": data.get("basicInfo", {}).get("nickname", "RUSHKEYㅤ1M"),
                    "AccountPinId": "Default",
                    "AccountRegion": data.get("basicInfo", {}).get("region", "IND"),
                    "AccountSeasonId": data.get("basicInfo", {}).get("seasonId", 45),
                    "AccountType": data.get("basicInfo", {}).get("accountType", 1),
                    "BrMaxRank": data.get("basicInfo", {}).get("maxRank", 326),
                    "BrRankPoint": data.get("basicInfo", {}).get("rankingPoints", 6317),
                    "CsMaxRank": data.get("basicInfo", {}).get("csMaxRank", 322),
                    "CsRankPoint": data.get("basicInfo", {}).get("csRankingPoints", 134),
                    "EquippedWeapon": data.get("basicInfo", {}).get("weaponSkinShows", [907104822, 912048002, 914048001]),
                    "EvoBadgeAccess": False,
                    "Iscelebrity": False,
                    "PrimeLevel": 7,
                    "ReleaseVersion": data.get("basicInfo", {}).get("releaseVersion", "OB49"),
                    "ShowBrRank": data.get("basicInfo", {}).get("showBrRank", True),
                    "ShowCsRank": data.get("basicInfo", {}).get("showCsRank", True),
                    "Title": data.get("basicInfo", {}).get("title", 904090026),
                    "hasElitePass": data.get("basicInfo", {}).get("hasElitePass", True)
                },
                "AccountProfileInfo": {
                    "EquippedOutfit": data.get("profileInfo", {}).get("clothes", [203038035, 214048003, 204000181, 211046056, 205043033]),
                    "EquippedSkills": data.get("profileInfo", {}).get("equipedSkills", [16, 2106, 8, 1, 16, 1206, 8, 2, 16, 6906, 8, 3, 16, 606]),
                    "characterid": data.get("profileInfo", {}).get("avatarId", 102000007)
                },
                "GuildInfo": {
                    "GuildCapacity": data.get("clanBasicInfo", {}).get("capacity", 40),
                    "GuildID": data.get("clanBasicInfo", {}).get("clanId", 3040835225),
                    "GuildLevel": data.get("clanBasicInfo", {}).get("clanLevel", 4),
                    "GuildMember": data.get("clanBasicInfo", {}).get("memberNum", 7),
                    "GuildName": data.get("clanBasicInfo", {}).get("clanName", "ᴘʀɪᴛᴜㅤɪsㅤʟɪᴠ"),
                    "GuildOwner": data.get("clanBasicInfo", {}).get("captainId", 995431726)
                },
                "captainBasicInfo": {
                    "accountId": data.get("clanBasicInfo", {}).get("captainId", 995431726),
                    "accountType": 1,
                    "badgeCnt": 61,
                    "badgeId": 1001000085,
                    "bannerId": 901000053,
                    "createAt": 1557795523,
                    "csMaxRank": 321,
                    "csRank": 321,
                    "csRankingPoints": 92,
                    "exp": 4127840,
                    "headPic": 902044014,
                    "lastLoginAt": 1749746133,
                    "level": 74,
                    "liked": 33441,
                    "maxRank": 323,
                    "nickname": "ᴘʀɪᴛᴜㅤɪsㅤʟɪᴠ",
                    "pinId": 910045001,
                    "rank": 323,
                    "rankingPoints": 4787,
                    "region": "IND",
                    "releaseVersion": "OB49",
                    "seasonId": 45,
                    "showBrRank": True,
                    "showCsRank": True,
                    "title": 904090026
                },
                "creditScoreInfo": {
                    "creditScore": data.get("creditScoreInfo", {}).get("creditScore", 100),
                    "periodicSummaryEndTime": data.get("creditScoreInfo", {}).get("periodicSummaryEndTime", 1749704085),
                    "periodicSummaryStartTime": 1749963285,
                    "rewardState": "REWARD_STATE_INVALID"
                },
                "petInfo": {
                    "exp": data.get("petInfo", {}).get("exp", 6000),
                    "id": data.get("petInfo", {}).get("id", 1300000117),
                    "isMarkedStar": False,
                    "isSelected": data.get("petInfo", {}).get("isSelected", True),
                    "level": data.get("petInfo", {}).get("level", 7),
                    "selectedSkillId": data.get("petInfo", {}).get("selectedSkillId", 1315000011),
                    "skinId": data.get("petInfo", {}).get("skinId", 1310000175)
                },
                "socialinfo": {
                    "AccountLanguage": "CN_TRADITIONAL",
                    "AccountPreferMode": "CASUAL_MODES",
                    "AccountPreferRank": "BR_RANKED",
                    "AccountSignature": "[B][00FFFF]EVOLVED - UNLEASHED - UNDENIABLE",
                    "ActiveDays": "FLEXIBLE",
                    "ActiveTime": "NIGHTIME"
                }
            },
            {
                "CraftlandInfo": {
                    "maps": [
                        {
                            "MapCode": map_info.get("MapCode", "#FREEFIREFEBB4B285F5A973E8975C8FECB32C2B84805"),
                            "MapTitle": map_info.get("MapTitle", "8P_SUPER_CREATOR_MODE"),
                            "description": map_info.get("description", "[B][00FF00][C]YT - RUSHKEY\n[FFFF00]SUBSCRIBE [FFFFFF]AND SUPPORT US FOR MORE MAPS")
                        }
                    ]
                }
            }
        ]
        
        return response

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
    map_code = request.args.get('map_code', 'FREEFIREFEBB4B285F5A973E8975C8FECB32C2B84805')

    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    if not region:
        return jsonify({"error": "Please provide REGION."}), 400

    try:
        return_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
        return jsonify(return_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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