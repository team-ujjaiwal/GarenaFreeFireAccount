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
DEFAULT_MAP_CODE = "FFBR"  # Default map code to fetch

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# [Previous helper functions remain the same...]

async def GetAccountInformation(uid, unk, region, endpoint):
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")
    
    # Get token info first
    token, lock, server = await get_token_info(region)
    
    # Prepare headers
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
        # First get player info
        player_payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
        player_data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, player_payload)
        player_resp = await client.post(server+endpoint, data=player_data_enc, headers=headers)
        player_data = json.loads(json_format.MessageToJson(
            decode_protobuf(player_resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
        ))
        
        # Then get default map info
        try:
            map_request = AccountPersonalShow_pb2.MapRequest()
            map_request.map_code = DEFAULT_MAP_CODE
            map_payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, map_request.SerializeToString())
            
            # Get both map and craftland info
            map_resp, craftland_resp = await asyncio.gather(
                client.post(server+"/GetMapInfo", data=map_payload, headers=headers),
                client.post(server+"/GetCraftlandInfo", data=map_payload, headers=headers)
            )
            
            # Decode responses
            map_info = AccountPersonalShow_pb2.MapInfo()
            map_info.ParseFromString(map_resp.content)
            
            craftland_info = AccountPersonalShow_pb2.CraftlandInfo()
            craftland_info.ParseFromString(craftland_resp.content)
            
            map_data = {
                "map_info": json_format.MessageToDict(map_info),
                "craftland_info": json_format.MessageToDict(craftland_info)
            }
        except Exception as e:
            map_data = {"error": f"Failed to fetch map info: {str(e)}"}
        
        return {
            "player_info": player_data,
            "map_info": map_data
        }

# [Keep the rest of the code the same...]

@app.route('/player-info')
@cached_endpoint()
def get_account_info():
    region = request.args.get('region')
    uid = request.args.get('uid')

    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    if not region:
        return jsonify({"error": "Please provide REGION."}), 400

    try:
        return_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
        formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
        return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
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