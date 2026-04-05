# mitmweb_handlers.py
# Chạy: mitmweb -s fix.py
from mitmproxy import http
import datetime
import os
import binascii
import base64
import ChooseEmote_pb2
import ChooseClothes_pb2  # Import cho ChooseClothes protobuf
# import LoginResNew_pb2 # Import cho LoginResNew protobuf
import GetPlayerPersonalShow_pb2 # Import cho GetPlayerPersonalShow protobuf
import ChooseShow_pb2  # Import cho ChooseShow protobuf
import blackboxprotobuf # Để debug nếu cần
import gzip # Để xử lý gzip nếu cần
from google.protobuf.descriptor import FieldDescriptor
# Import AES module với class AESUtils
try:
    from AES import AESUtils
    aes_utils = AESUtils()
    print("✓ AESUtils module loaded successfully")
except ImportError as e:
    print(f"⚠ AES module error: {e}")
    # Tạo dummy AESUtils class
    class DummyAESUtils:
        key_base64 = "WWcmdGMlREV1aDYlWmNeOA=="
        iv_base64 = "Nm95WkRyMjJFM3ljaGpNJQ=="
        def decrypt_aes_cbc(self, ciphertext_hex):
            print(f" Dummy decrypt: {ciphertext_hex[:50]}...")
            return bytes.fromhex(ciphertext_hex) if ciphertext_hex else b""
        def decrypt_aes_cbc_bytes(self, data_bytes):
            print(f" Dummy decrypt bytes: {len(data_bytes)} bytes")
            return data_bytes # Dummy: return raw
    aes_utils = DummyAESUtils()

def _make_headers(body: bytes) -> dict:
    return {
        "vary": "Accept-Encoding",
        "date": datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
        "content-length": str(len(body)),
        "content-type": "application/octet-stream",
        "X-Mitmweb-Modified": "true"
    }

def octet_stream_to_hex(octet_stream):
    """Chuyển đổi bytes thành hex."""
    return binascii.hexlify(octet_stream).decode()

def hex_to_octet_stream(hex_str: str) -> bytes:
    """Chuyển đổi hex thành bytes."""
    return bytes.fromhex(hex_str) if hex_str else b""

def debug_protobuf(data, label="Unknown"):
    """Debug protobuf bằng blackboxprotobuf"""
    try:
        msg, typedef = blackboxprotobuf.decode_message(data)
        print(f" 🔍 {label} blackbox decode (full fields):")
        for k, v in sorted(msg.items()):  # Sort để dễ đọc
            kt = type(k).__name__
            if isinstance(v, bytes):
                try:
                    print(f"  ({kt}) {k}: '{v.decode('utf-8')}' (len={len(v)})")
                except:
                    print(f"  ({kt}) {k}: {v.hex()[:50]}... (bytes, len={len(v)})")
            elif isinstance(v, (dict, list)):
                print(f"  ({kt}) {k}: {type(v)} (len={len(v)})")
            else:
                print(f"  ({kt}) {k}: {v}")
        return msg
    except Exception as e:
        print(f" ⚠ {label} blackbox decode failed: {e}")
        return None

# Biến global để lưu emotes (dict slot: item_id để match map structure) - IN-MEMORY ONLY
stored_emotes = {}
# Biến global để lưu banner_id_primary từ ChooseBanner request (sử dụng cho clan_id)
stored_banner_id = None
# Biến global để lưu avatar_id từ ChooseHeadPic request (sử dụng cho title_id)
stored_avatar_id = None
# Biến global để lưu clothes_id và clothes_hash từ ChangeClothes request
stored_clothes_id = None
stored_clothes_hash = None
# Biến global để lưu slot_string và slot_hash từ ChooseSlotsAndShow request
stored_slot_string = None
stored_slot_hash = None
# Biến global để lưu show_slot_id từ ChooseShow request
stored_show_slot_id = None

def _safe_get(d, key, default=0):
    """Lấy giá trị từ dict thử cả key int và string, trả default nếu không tìm thấy."""
    if d is None or not isinstance(d, dict):
        return default
    # thử key chính xác
    if key in d:
        return d[key]
    # thử dạng string
    sk = str(key)
    if sk in d:
        return d[sk]
    # thử dạng int nếu key là string
    try:
        ik = int(key)
        if ik in d:
            return d[ik]
    except Exception:
        pass
    return default

def try_decode_response_body(body: bytes, aes_utils_instance):
    """Thử các phương pháp decode response tương tự decoder script"""
    raw = body
    pt = None
    # 1. Try direct parse protobuf
    try:
        msg, _ = blackboxprotobuf.decode_message(raw)
        print(f" ✅ Direct protobuf parse OK")
        return raw # Trả raw nếu parse được trực tiếp
    except:
        pass
    # 2. Try AES decrypt without IV (hex to str first)
    try:
        hex_str = raw.hex()
        dec = aes_utils_instance.decrypt_aes_cbc(hex_str)
        if dec[:2] == b"\x1f\x8b":
            dec = gzip.decompress(dec)
            print(f" ✅ AES decrypt (no IV) + gzip OK")
        pt = dec
    except Exception as e:
        print(f" ⚠ AES no IV failed: {e}")
    # 3. If not, try AES with IV prefix
    if not pt and len(raw) > 16:
        try:
            iv = raw[:16]
            cipher = raw[16:]
            key = base64.b64decode(aes_utils_instance.key_base64)
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            cipher_obj = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            dec = cipher_obj.decryptor().update(cipher) + cipher_obj.decryptor().finalize()
            pad = dec[-1]
            if 1 <= pad <= 16:
                dec = dec[:-pad]
            if dec[:2] == b"\x1f\x8b":
                dec = gzip.decompress(dec)
                print(f" ✅ AES IV prefix + gzip OK")
            pt = dec
        except Exception as e:
            print(f" ⚠ AES IV prefix failed: {e}")
    # 4. If still not, try AES decrypt bytes directly (alternative method)
    if not pt:
        try:
            dec = aes_utils_instance.decrypt_aes_cbc_bytes(raw)
            if dec[:2] == b"\x1f\x8b":
                dec = gzip.decompress(dec)
                print(f" ✅ AES decrypt_bytes + gzip OK")
            pt = dec
        except Exception as e:
            print(f" ⚠ AES decrypt_bytes failed: {e}")
    # 5. Fallback: return raw if nothing works
    if not pt:
        print(" ⚠ No decoding succeeded, using raw")
        pt = raw
    # Try parse pt as protobuf to confirm
    try:
        msg, _ = blackboxprotobuf.decode_message(pt)
        print(f" ✅ Final protobuf parse OK on decoded data")
        return pt
    except:
        print(" ⚠ Could not parse decoded data as protobuf")
        return raw # Fallback to raw

# Merge function for GetPlayerPersonalShow
LOCAL_BIN_PATH = "GetPlayerPersonalShow.bin"

BLOCK_FIELDS = {
    "field_65",
    "cosmetic_skin",
    "kills",
    "field_76",
    "field_75",
    "matches_played",
    "field_48",
    "experience",
    "field_16",
    "field_17",
    "daily_challenges",
    "main_weapon",
    "field_23",
    "headshot_percentage",
    "current_rank",
    "rank",
    "profile",
    "session",
    "settings",
    "currencies"
    # Lưu ý: Không include "clans" để merge, sau đó override
}

def merge_msg(src, dst):
    for field in src.DESCRIPTOR.fields:
        # Bỏ qua các field không được phép merge
        if field.name in BLOCK_FIELDS:
            continue

        src_value = getattr(src, field.name)

        # repeated
        if field.label == FieldDescriptor.LABEL_REPEATED:
            dst_list = getattr(dst, field.name)

            if field.type == FieldDescriptor.TYPE_MESSAGE:
                while len(dst_list) < len(src_value):
                    dst_list.add()

                for i in range(len(src_value)):
                    merge_msg(src_value[i], dst_list[i])
            else:
                dst_list[:] = src_value

        # single
        else:
            if field.type == FieldDescriptor.TYPE_MESSAGE:
                merge_msg(src_value, getattr(dst, field.name))
            else:
                setattr(dst, field.name, src_value)

def create_clan_logo_protobuf():
    """Tạo clan_logo protobuf message từ dữ liệu mẫu"""
    # Từ debug: clan_logo: "{'25375000': 205000000, '25500000': 208000000, '26750000': 211000000}"
    # Đây là một map protobuf với key là string, value là int
    
    try:
        # Tạo message bằng blackboxprotobuf
        message = {
            '25375000': 205000000,
            '25500000': 208000000, 
            '26750000': 211000000
        }
        
        # Encode thành protobuf bytes
        typedef = {'1': {'type': 'int', 'name': ''}}
        encoded_bytes, _ = blackboxprotobuf.encode_message(message, typedef)
        
        print(f"   Created clan_logo protobuf: {message}")
        print(f"   Encoded bytes (hex): {encoded_bytes.hex()}")
        
        return encoded_bytes
    except Exception as e:
        print(f"   ⚠ Error creating clan_logo protobuf: {e}")
        # Fallback: trả về bytes mẫu
        return b'\xc0\x91\xe6`\xc0\x9a\xe0a\x80\x96\xa3a\x80\xa8\x97c\x80\xc3\x85f\xc0\xb5\xced'

def encode_varint(n):
    buf = b''
    while True:
        towrite = n & 0x7f
        n >>= 7
        if n:
            buf += bytes([towrite | 0x80])
        else:
            buf += bytes([towrite])
            break
    return buf

def encode_nested_bytes_msg(slot_str_bytes, slot_hash_bytes):
    """Manually encode protobuf message with nested field 1 containing fields 7 and 9 as bytes"""
    # Create nested message first
    nested = b''
    # Field 7 in nested: tag 0x3A (field 7, wire 2), len varint, data
    nested += b'\x3A' + encode_varint(len(slot_str_bytes)) + slot_str_bytes
    # Field 9 in nested: tag 0x4A (field 9, wire 2), len varint, data
    nested += b'\x4A' + encode_varint(len(slot_hash_bytes)) + slot_hash_bytes
    # Outer field 1: tag 0x0A (field 1, wire 2), len varint of nested, nested
    msg = b'\x0A' + encode_varint(len(nested)) + nested
    return msg

def request(flow: http.HTTPFlow) -> None:
    global stored_emotes, stored_banner_id, stored_avatar_id, stored_clothes_id, stored_clothes_hash, stored_slot_string, stored_slot_hash, stored_show_slot_id
    """Xử lý request ChooseEmote (được mã hóa AES)"""
    host = flow.request.host
    path = flow.request.path
    method = flow.request.method
    # Parse request ChooseEmote
    if host == "clientbp.ggpolarbear.com" and path == "/ChooseEmote" and method == "POST":
        print(f"\n{'='*70}")
        print(f"📥 CHOOSE EMOTE REQUEST - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        try:
            # 1. Lấy raw request body (16 bytes encrypted)
            req_body = flow.request.content
            print(f" 📦 Raw request: {len(req_body)} bytes")
            print(f" Hex: {req_body.hex()}")
            # 2. Giải mã AES-CBC với AESUtils.decrypt_aes_cbc()
            print(f" 🔓 Decrypting with AESUtils.decrypt_aes_cbc()...")
            # Chuyển bytes sang hex string
            ciphertext_hex = req_body.hex()
            decrypted_data = aes_utils.decrypt_aes_cbc(ciphertext_hex)
            print(f" ✅ Decrypted: {len(decrypted_data)} bytes")
            print(f" Hex: {decrypted_data.hex()}")
            # 3. Parse từ blackboxprotobuf (vì protobuf definition sai)
            debug_msg = debug_protobuf(decrypted_data, "Request protobuf")
            # 4. Xử lý sub[6]: check nếu list (multi) hay dict (single)
            sub = _safe_get(debug_msg, 6, None)
            processed = 0
            if sub:
                if isinstance(sub, list):
                    # Multi mode: direct list of slot dicts
                    print(f" 🔄 Multi-slot mode: processing {len(sub)} actions")
                    for slot_dict in sub:
                        if isinstance(slot_dict, dict):
                            raw_slot = _safe_get(slot_dict, 1, 0)
                            raw_item = _safe_get(slot_dict, 2, 0)
                            try:
                                slot = int(raw_slot)
                            except Exception:
                                slot = 0
                            try:
                                item_id = int(raw_item)
                            except Exception:
                                item_id = 0
                            if slot > 0:
                                if item_id > 0:
                                    old_item = stored_emotes.get(slot, None)
                                    stored_emotes[slot] = item_id
                                    if old_item is not None:
                                        print(f" 🔄 Updated slot {slot} from {old_item} to {item_id}")
                                    else:
                                        print(f" ✅ Added new emote slot {slot} with item_id {item_id}")
                                else:
                                    # Remove slot
                                    if slot in stored_emotes:
                                        del stored_emotes[slot]
                                        print(f" 🗑️ Removed slot {slot} (unequip)")
                                    else:
                                        print(f" ⚠ Slot {slot} not found, nothing to remove")
                                processed += 1
                            else:
                                print(f" ⚠ Invalid slot {slot}, skipping")
                        else:
                            print(f" ⚠ Invalid slot_dict: {type(slot_dict)}")
                elif isinstance(sub, dict):
                    # Single mode: {'1': slot, '2': item_id?}
                    print(f" 🔄 Single-slot mode")
                    raw_slot = _safe_get(sub, 1, 0)
                    raw_item = _safe_get(sub, 2, 0)
                    try:
                        slot = int(raw_slot)
                    except Exception:
                        slot = 0
                    try:
                        item_id = int(raw_item)
                    except Exception:
                        item_id = 0
                    if slot > 0:
                        if item_id > 0:
                            old_item = stored_emotes.get(slot, None)
                            stored_emotes[slot] = item_id
                            if old_item is not None:
                                print(f" 🔄 Updated slot {slot} from {old_item} to {item_id}")
                            else:
                                print(f" ✅ Added new emote slot {slot} with item_id {item_id}")
                        else:
                            # Remove slot
                            if slot in stored_emotes:
                                del stored_emotes[slot]
                                print(f" 🗑️ Removed slot {slot} (unequip)")
                            else:
                                print(f" ⚠ Slot {slot} not found, nothing to remove")
                        processed += 1
                    else:
                        print(f" ⚠ Invalid slot, skipping")
                else:
                    print(f" ⚠ Unexpected sub type: {type(sub)}")
            else:
                print(f" ⚠ No valid sub[6] for slots")
            print(f" Processed {processed} slot actions")
            # Không lưu file nữa - chỉ in-memory
        except Exception as e:
            print(f" ❌ Error processing request: {e}")
            import traceback
            traceback.print_exc()
        print(f"{'='*70}")
    # Parse request ChooseBanner (tương tự ChooseEmote, decrypt và lưu banner_id_primary) - UPDATE DEBUG
    if host == "clientbp.ggpolarbear.com" and path == "/ChooseBanner" and method == "POST":
        print(f"\n{'='*70}")
        print(f"📥 CHOOSE BANNER REQUEST - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        try:
            # 1. Lấy raw request body (encrypted)
            req_body = flow.request.content
            print(f" 📦 Raw request: {len(req_body)} bytes")
            print(f" Hex: {req_body.hex()}")
            # 2. Giải mã AES-CBC với AESUtils.decrypt_aes_cbc()
            print(f" 🔓 Decrypting with AESUtils.decrypt_aes_cbc()...")
            # Chuyển bytes sang hex string
            ciphertext_hex = req_body.hex()
            decrypted_data = aes_utils.decrypt_aes_cbc(ciphertext_hex)
            print(f" ✅ Decrypted: {len(decrypted_data)} bytes")
            print(f" Hex: {decrypted_data.hex()}")
            # 3. Parse từ blackboxprotobuf - BÂY GIỜ PRINT FULL ĐỂ DEBUG FIELD NÀO LÀ BANNER
            debug_msg = debug_protobuf(decrypted_data, "ChooseBanner Request protobuf")
            # 4. Thử lấy field cho banner_id_primary (thử field 1, hoặc scan tất cả fields int >0 để fallback)
            raw_banner = _safe_get(debug_msg, 1, None)
            # Fallback: Scan tất cả fields, tìm int lớn (giả sử banner_id là số lớn như 90xxxx)
            if raw_banner is None:
                print(" 🔍 Scanning all fields for potential banner_id (int > 900000000)...")
                for k, v in debug_msg.items():
                    if isinstance(v, int) and v > 900000000:
                        raw_banner = v
                        print(f"   → Found candidate in field {k}: {v}")
                        break
            if raw_banner is not None:
                try:
                    banner_id = int(raw_banner)
                except Exception:
                    print(f" ⚠ Invalid banner_id {raw_banner}, skipping")
                    banner_id = None
                else:
                    old_banner = stored_banner_id
                    stored_banner_id = banner_id
                    if old_banner is not None:
                        print(f" 🔄 Updated banner_id_primary from {old_banner} to {banner_id}")
                    else:
                        print(f" ✅ Set new banner_id_primary to {banner_id}")
            else:
                # Fallback set default nếu parse fail
                stored_banner_id = 901037021  # Default
                print(f" ⚠ No valid banner_id found, fallback set to default {stored_banner_id}")
            # Không lưu file nữa - chỉ in-memory
        except Exception as e:
            print(f" ❌ Error processing ChooseBanner request: {e}")
            import traceback
            traceback.print_exc()
            # Fallback
            stored_banner_id = 901037021
            print(f" ⚠ Fallback set banner_id to default {stored_banner_id}")
        print(f"{'='*70}")
    # Parse request ChooseHeadPic (tương tự ChooseBanner, decrypt và lưu avatar_id)
    if host == "clientbp.ggpolarbear.com" and path == "/ChooseHeadPic" and method == "POST":
        print(f"\n{'='*70}")
        print(f"📥 CHOOSE HEAD PIC REQUEST - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        try:
            # 1. Lấy raw request body (encrypted)
            req_body = flow.request.content
            print(f" 📦 Raw request: {len(req_body)} bytes")
            print(f" Hex: {req_body.hex()}")
            # 2. Giải mã AES-CBC với AESUtils.decrypt_aes_cbc()
            print(f" 🔓 Decrypting with AESUtils.decrypt_aes_cbc()...")
            # Chuyển bytes sang hex string
            ciphertext_hex = req_body.hex()
            decrypted_data = aes_utils.decrypt_aes_cbc(ciphertext_hex)
            print(f" ✅ Decrypted: {len(decrypted_data)} bytes")
            print(f" Hex: {decrypted_data.hex()}")
            # 3. Parse từ blackboxprotobuf
            debug_msg = debug_protobuf(decrypted_data, "ChooseHeadPic Request protobuf")
            # 4. Xử lý field cho avatar_id (field 1 trực tiếp)
            raw_avatar = _safe_get(debug_msg, 1, None)
            if raw_avatar is not None:
                try:
                    avatar_id = int(raw_avatar)
                except Exception:
                    print(f" ⚠ Invalid avatar_id {raw_avatar}, skipping")
                else:
                    old_avatar = stored_avatar_id
                    stored_avatar_id = avatar_id
                    if old_avatar is not None:
                        print(f" 🔄 Updated avatar_id from {old_avatar} to {avatar_id}")
                    else:
                        print(f" ✅ Set new avatar_id to {avatar_id}")
            else:
                print(f" ⚠ No valid avatar_id in field 1 found")
            # Không lưu file nữa - chỉ in-memory
        except Exception as e:
            print(f" ❌ Error processing ChooseHeadPic request: {e}")
            import traceback
            traceback.print_exc()
        print(f"{'='*70}")
    # Parse request ChangeClothes (tương tự ChooseEmote, decrypt và lưu clothes_id + hash)
    if host == "clientbp.ggpolarbear.com" and path == "/ChangeClothes" and method == "POST":
        print(f"\n{'='*70}")
        print(f"📥 CHANGE CLOTHES REQUEST - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        try:
            # 1. Lấy raw request body (encrypted)
            req_body = flow.request.content
            print(f" 📦 Raw request: {len(req_body)} bytes")
            print(f" Hex: {req_body.hex()}")
            # 2. Giải mã AES-CBC với AESUtils.decrypt_aes_cbc()
            print(f" 🔓 Decrypting with AESUtils.decrypt_aes_cbc()...")
            # Chuyển bytes sang hex string
            ciphertext_hex = req_body.hex()
            decrypted_data = aes_utils.decrypt_aes_cbc(ciphertext_hex)
            print(f" ✅ Decrypted: {len(decrypted_data)} bytes")
            print(f" Hex: {decrypted_data.hex()}")
            # 3. Parse từ blackboxprotobuf
            debug_msg = debug_protobuf(decrypted_data, "ChangeClothes Request protobuf")
            # 4. Lưu field 1 (id), field 2 (hash), field 3 (quantity, nhưng không dùng cho response)
            raw_id = _safe_get(debug_msg, 1, None)
            raw_hash = _safe_get(debug_msg, 2, None)
            raw_quantity = _safe_get(debug_msg, 3, None)
            if raw_id is not None:
                try:
                    clothes_id = int(raw_id)
                    stored_clothes_id = clothes_id
                    print(f" ✅ Stored clothes_id: {clothes_id}")
                except Exception:
                    print(f" ⚠ Invalid clothes_id {raw_id}, skipping")
            if raw_hash is not None:
                try:
                    # Treat as binary hash and hexlify to string
                    if isinstance(raw_hash, bytes):
                        clothes_hash = binascii.hexlify(raw_hash).decode('ascii')
                    else:
                        clothes_hash = str(raw_hash)
                    stored_clothes_hash = clothes_hash
                    print(f" ✅ Stored clothes_hash: {clothes_hash}")
                except Exception:
                    print(f" ⚠ Invalid clothes_hash {raw_hash}, skipping")
            if raw_quantity is not None:
                print(f" 📝 clothes_quantity (unused): {raw_quantity}")
            else:
                print(f" ⚠ No valid fields found")
            # Không lưu file nữa - chỉ in-memory
        except Exception as e:
            print(f" ❌ Error processing ChangeClothes request: {e}")
            import traceback
            traceback.print_exc()
        print(f"{'='*70}")
    # Parse request ChooseSlotsAndShow (tương tự ChangeClothes, decrypt và lưu slot_string + slot_hash) - REVERT TO BLACKBOX
    if host == "clientbp.ggpolarbear.com" and path == "/ChooseSlotsAndShow" and method == "POST":
        print(f"\n{'='*70}")
        print(f"📥 CHOOSE SLOTS AND SHOW REQUEST - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        try:
            # 1. Lấy raw request body (encrypted)
            req_body = flow.request.content
            print(f" 📦 Raw request: {len(req_body)} bytes")
            print(f" Hex: {req_body.hex()}")
            # 2. Giải mã AES-CBC với AESUtils.decrypt_aes_cbc()
            print(f" 🔓 Decrypting with AESUtils.decrypt_aes_cbc()...")
            # Chuyển bytes sang hex string
            ciphertext_hex = req_body.hex()
            decrypted_data = aes_utils.decrypt_aes_cbc(ciphertext_hex)
            print(f" ✅ Decrypted: {len(decrypted_data)} bytes")
            print(f" Hex: {decrypted_data.hex()}")
            # 3. Parse từ blackboxprotobuf
            debug_msg = debug_protobuf(decrypted_data, "ChooseSlotsAndShow Request protobuf")
            # 4. Lưu field 1 (long hex string), field 2 (short hex)
            raw_slot_str = _safe_get(debug_msg, 1, None)
            raw_slot_hash = _safe_get(debug_msg, 2, None)
            if raw_slot_str is not None:
                try:
                    # Treat as bytes and hexlify to string
                    if isinstance(raw_slot_str, bytes):
                        slot_string = binascii.hexlify(raw_slot_str).decode('ascii').lower()
                    else:
                        slot_string = str(raw_slot_str).lower()
                    stored_slot_string = slot_string
                    print(f" ✅ Stored slot_string: {slot_string[:50]}...")
                except Exception:
                    print(f" ⚠ Invalid slot_string {raw_slot_str}, skipping")
            if raw_slot_hash is not None:
                try:
                    # Treat as bytes and hexlify to string
                    if isinstance(raw_slot_hash, bytes):
                        slot_hash = binascii.hexlify(raw_slot_hash).decode('ascii').lower()
                    else:
                        slot_hash = str(raw_slot_hash).lower()
                    stored_slot_hash = slot_hash
                    print(f" ✅ Stored slot_hash: {slot_hash}")
                except Exception:
                    print(f" ⚠ Invalid slot_hash {raw_slot_hash}, skipping")
            else:
                print(f" ⚠ No valid fields found")
            # Không lưu file nữa - chỉ in-memory
        except Exception as e:
            print(f" ❌ Error processing ChooseSlotsAndShow request: {e}")
            import traceback
            traceback.print_exc()
        print(f"{'='*70}")
    # Parse request ChooseShow (tương tự ChangeClothes, decrypt và lưu show_slot_id)
    if host == "clientbp.ggpolarbear.com" and path == "/ChooseShow" and method == "POST":
        print(f"\n{'='*70}")
        print(f"📥 CHOOSE SHOW REQUEST - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        try:
            # 1. Lấy raw request body (encrypted)
            req_body = flow.request.content
            print(f" 📦 Raw request: {len(req_body)} bytes")
            print(f" Hex: {req_body.hex()}")
            # 2. Giải mã AES-CBC với AESUtils.decrypt_aes_cbc()
            print(f" 🔓 Decrypting with AESUtils.decrypt_aes_cbc()...")
            # Chuyển bytes sang hex string
            ciphertext_hex = req_body.hex()
            decrypted_data = aes_utils.decrypt_aes_cbc(ciphertext_hex)
            print(f" ✅ Decrypted: {len(decrypted_data)} bytes")
            print(f" Hex: {decrypted_data.hex()}")
            # 3. Parse từ blackboxprotobuf
            debug_msg = debug_protobuf(decrypted_data, "ChooseShow Request protobuf")
            # 4. Lưu field 1 (hex string)
            raw_show_id = _safe_get(debug_msg, 1, None)
            if raw_show_id is not None:
                if raw_show_id == '' or (isinstance(raw_show_id, dict) and len(raw_show_id) == 0):
                    stored_show_slot_id = ''
                    print(f" ✅ Stored empty show_slot_id")
                else:
                    try:
                        # Treat as bytes and hexlify to string
                        if isinstance(raw_show_id, bytes):
                            show_slot_id = binascii.hexlify(raw_show_id).decode('ascii').lower()
                        else:
                            show_slot_id = str(raw_show_id).lower()
                        # Validate it's a hex string
                        if all(c in '0123456789abcdef' for c in show_slot_id):
                            stored_show_slot_id = show_slot_id
                            print(f" ✅ Stored show_slot_id: {show_slot_id}")
                        else:
                            print(f" ⚠ Invalid hex in show_slot_id {show_slot_id}, skipping")
                    except Exception:
                        print(f" ⚠ Invalid show_slot_id {raw_show_id}, skipping")
            else:
                print(f" ⚠ No valid field 1 found")
            # Không lưu file nữa - chỉ in-memory
        except Exception as e:
            print(f" ❌ Error processing ChooseShow request: {e}")
            import traceback
            traceback.print_exc()
        print(f"{'='*70}")

def response(flow: http.HTTPFlow) -> None:
    global stored_emotes, stored_banner_id, stored_avatar_id, stored_clothes_id, stored_clothes_hash, stored_slot_string, stored_slot_hash, stored_show_slot_id
    host = flow.request.host
    path = flow.request.path
    method = flow.request.method
    # ChooseEmote - Response handler (GỬI PROTOBUF RAW, KHÔNG MÃ HÓA) - SỬ DỤNG EMOTES TỪ REQUEST VÀ BANNER/AVATAR TỪ CHOOSEBANNER/HEADPIC
    if host == "clientbp.ggpolarbear.com" and path == "/ChooseEmote" and method == "POST":
        print(f"\n{'='*70}")
        print(f"📤 CHOOSE EMOTE RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        try:
            # 1. Tạo response protobuf ChooseProfileRes
            res = ChooseEmote_pb2.ChooseProfileRes()
            # 2. Tạo ProfileInfo theo cấu trúc JSON CHÍNH XÁC
            profile_info = ChooseEmote_pb2.ProfileInfo()
            # 3. Đặt banner_id_primary từ stored_banner_id (không hardcode)
            default_banner = 901037021
            profile_info.banner_id_primary = stored_banner_id if stored_banner_id is not None else default_banner
            print(f" 🖼️ Using banner_id_primary: {profile_info.banner_id_primary} (from ChooseBanner request)")
            # 4. Đặt avatar_id từ stored_avatar_id (không hardcode)
            default_avatar = 902037031
            profile_info.avatar_id = stored_avatar_id if stored_avatar_id is not None else default_avatar
            print(f" 👤 Using avatar_id: {profile_info.avatar_id} (from ChooseHeadPic request)")
            profile_info.banner_id_override = 904990072 # Field 15 (để match "15" trong JSON gốc)
            # 5. Tạo equipped list (field 8) SỬ DỤNG stored_emotes TỪ REQUESTS
            # "8": {"1": [ {"1":slot, "2":item_id}, ... ]} - repeated slot messages
            equipped = ChooseEmote_pb2.ProfileList()
            if stored_emotes:
                for slot, item_id in sorted(stored_emotes.items()):
                    slot_msg = equipped.slot.add()
                    slot_msg.slot = int(slot)
                    slot_msg.item_id = int(item_id)
                print(f" 📊 Equipped emotes TỪ REQUESTS (field 8 with {len(stored_emotes)} slots):")
                for slot in sorted(stored_emotes):
                    print(f" - {{'1': {int(slot)}, '2': {int(stored_emotes[slot])}}}")
            else:
                print(f" 📊 No stored emotes (field 8 empty)")
            profile_info.equipped.CopyFrom(equipped)
            # KHÔNG THÊM patterns, raw_blob, pin_id (field 12), extra để match exact JSON structure
            # Chỉ có fields 5,6,8,15 trong "1" (profile_info)
            # 6. Gắn profile_info vào response (field 1)
            res.info.CopyFrom(profile_info)
            # 7. Serialize thành binary (KHÔNG MÃ HÓA - raw protobuf)
            proto_bytes = res.SerializeToString()
            # 8. Debug với blackboxprotobuf để verify exact structure
            debug_msg = debug_protobuf(proto_bytes, "Response protobuf")
            # 9. Tạo response với raw protobuf
            body = proto_bytes
        except Exception as e:
            print(f" ❌ Error creating response: {e}")
            import traceback
            traceback.print_exc()
            body = b""
        # 10. Gửi response (raw protobuf, không mã hóa)
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"\n 📤 Sent RAW protobuf response WITH REQUEST EMOTES & BANNER & AVATAR ({len(body)} bytes)")
        print(f"{'='*70}\n")
    # ChooseBanner - Response handler (tương tự, gửi raw protobuf với banner_id từ request)
    if host == "clientbp.ggpolarbear.com" and path == "/ChooseBanner" and method == "POST":
        print(f"\n{'='*70}")
        print(f"📤 CHOOSE BANNER RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        try:
            # Giả sử có pb2 cho ChooseBannerRes, nhưng dùng ChooseEmote_pb2 tương tự hoặc tạo simple
            # Để đơn giản, tạo response tương tự ChooseProfileRes nhưng chỉ với banner
            # Sử dụng blackbox cho debug, nhưng serialize simple message
            # Tạo simple res (giả sử structure: field 1: banner_id)
            simple_res = ChooseEmote_pb2.ChooseProfileRes() # Reuse for simplicity
            profile_info = ChooseEmote_pb2.ProfileInfo()
            profile_info.banner_id_primary = stored_banner_id if stored_banner_id is not None else 901037021
            simple_res.info.CopyFrom(profile_info)
            proto_bytes = simple_res.SerializeToString()
            # Debug
            debug_msg = debug_protobuf(proto_bytes, "ChooseBanner Response protobuf")
            body = proto_bytes
        except Exception as e:
            print(f" ❌ Error creating ChooseBanner response: {e}")
            import traceback
            traceback.print_exc()
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"\n 📤 Sent RAW protobuf response WITH BANNER ({len(body)} bytes)")
        print(f"{'='*70}\n")
    # ChooseHeadPic - Response handler (tương tự ChooseBanner, gửi raw protobuf với avatar_id từ request)
    if host == "clientbp.ggpolarbear.com" and path == "/ChooseHeadPic" and method == "POST":
        print(f"\n{'='*70}")
        print(f"📤 CHOOSE HEAD PIC RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        try:
            # Tạo simple res (giả sử structure: field 1: avatar_id)
            simple_res = ChooseEmote_pb2.ChooseProfileRes() # Reuse for simplicity
            profile_info = ChooseEmote_pb2.ProfileInfo()
            profile_info.avatar_id = stored_avatar_id if stored_avatar_id is not None else 902037031
            simple_res.info.CopyFrom(profile_info)
            proto_bytes = simple_res.SerializeToString()
            # Debug
            debug_msg = debug_protobuf(proto_bytes, "ChooseHeadPic Response protobuf")
            body = proto_bytes
        except Exception as e:
            print(f" ❌ Error creating ChooseHeadPic response: {e}")
            import traceback
            traceback.print_exc()
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"\n 📤 Sent RAW protobuf response WITH AVATAR ({len(body)} bytes)")
        print(f"{'='*70}\n")
    # ChangeClothes - Response handler (gửi raw protobuf với id và hash từ request)
    if host == "clientbp.ggpolarbear.com" and path == "/ChangeClothes" and method == "POST":
        print(f"\n{'='*70}")
        print(f"📤 CHANGE CLOTHES RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        try:
            body = b""
            default_item_id = 102000007
            default_hash = "9b98e9609ba1e361db9ca6619bbcd16480c38566"
            item_id = stored_clothes_id if stored_clothes_id is not None else default_item_id
            auth_token = stored_clothes_hash if stored_clothes_hash else default_hash
            # 1. Tạo response protobuf ChooseClothesRes
            res = ChooseClothes_pb2.ChooseClothesRes()
            # 2. Tạo ResponseData
            data = ChooseClothes_pb2.ResponseData()
            data.item_id = item_id
            data.auth_token = auth_token
            print(f" 👕 Using item_id: {data.item_id} (from ChangeClothes request or default)")
            print(f" 🔑 Using auth_token: {data.auth_token} (from ChangeClothes request or default)")
            # 3. Gắn data vào response (field 1)
            res.data.CopyFrom(data)
            # 4. Serialize thành binary (KHÔNG MÃ HÓA - raw protobuf)
            proto_bytes = res.SerializeToString()
            # 5. Debug với blackboxprotobuf để verify exact structure
            debug_msg = debug_protobuf(proto_bytes, "ChangeClothes Response protobuf")
            body = proto_bytes
        except Exception as e:
            print(f" ❌ Error creating ChangeClothes response: {e}")
            import traceback
            traceback.print_exc()
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"\n 📤 Sent RAW protobuf response WITH CLOTHES ID & AUTH_TOKEN ({len(body)} bytes)")
        print(f"{'='*70}\n")
    # ChooseSlotsAndShow - Response handler (gửi raw protobuf với slot_string và slot_hash từ request, FIXED WITH MANUAL ENCODE)
    if host == "clientbp.ggpolarbear.com" and path == "/ChooseSlotsAndShow" and method == "POST":
        print(f"\n{'='*70}")
        print(f"📤 CHOOSE SLOTS AND SHOW RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        try:
            body = b""
            default_slot_string = "000081e9c4af0300000000000000000000b7a0cbb00300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            default_slot_hash = "b7a0cbb003"
            slot_string = stored_slot_string if stored_slot_string else default_slot_string
            slot_hash = stored_slot_hash if stored_slot_hash else default_slot_hash
            print(f" 🎰 Using slot_string: {slot_string[:50]}... (from ChooseSlotsAndShow request or default)")
            print(f" 🔑 Using slot_hash: {slot_hash} (from ChooseSlotsAndShow request or default)")
            # 1. Manually encode the protobuf message (nested structure)
            slot_str_bytes = bytes.fromhex(slot_string)
            slot_hash_bytes = bytes.fromhex(slot_hash)
            proto_bytes = encode_nested_bytes_msg(slot_str_bytes, slot_hash_bytes)
            # 2. Debug với blackboxprotobuf để verify exact structure
            debug_msg = debug_protobuf(proto_bytes, "ChooseSlotsAndShow Response protobuf")
            body = proto_bytes
        except Exception as e:
            print(f" ❌ Error creating ChooseSlotsAndShow response: {e}")
            import traceback
            traceback.print_exc()
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"\n 📤 Sent RAW protobuf response WITH SLOT_STRING & SLOT_HASH ({len(body)} bytes)")
        print(f"{'='*70}\n")
    # ChooseShow - Response handler (gửi raw protobuf với show_slot_id từ request)
    if host == "clientbp.ggpolarbear.com" and path == "/ChooseShow" and method == "POST":
        print(f"\n{'='*70}")
        print(f"📤 CHOOSE SHOW RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        try:
            body = b""
            default_show_slot_id = "f7ddd0b003"
            show_slot_id = stored_show_slot_id if stored_show_slot_id is not None else default_show_slot_id
            # Special handling for empty request
            if show_slot_id == '':
                inner_data_show_slot_id = b''
                print(f" 🎭 Using empty show_slot_id (matching request)")
            else:
                # Validate show_slot_id is valid hex before using
                if isinstance(show_slot_id, str) and all(c in '0123456789abcdef' for c in show_slot_id.lower()):
                    inner_data_show_slot_id = bytes.fromhex(show_slot_id)
                    print(f" 🎭 Using show_slot_id: {show_slot_id} (from ChooseShow request)")
                else:
                    inner_data_show_slot_id = bytes.fromhex(default_show_slot_id)
                    print(f" ⚠ Invalid show_slot_id '{show_slot_id}', falling back to default {default_show_slot_id}")
            # 1. Tạo response protobuf ChooseShowResponse
            res = ChooseShow_pb2.ChooseShowResponse()
            # 2. Set InnerData
            inner_data = res.data
            inner_data.show_slot_id = inner_data_show_slot_id
            # 3. Serialize thành binary (KHÔNG MÃ HÓA - raw protobuf)
            proto_bytes = res.SerializeToString()
            # 4. Debug với blackboxprotobuf để verify exact structure
            debug_msg = debug_protobuf(proto_bytes, "ChooseShow Response protobuf")
            body = proto_bytes
        except Exception as e:
            print(f" ❌ Error creating ChooseShow response: {e}")
            import traceback
            traceback.print_exc()
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"\n 📤 Sent RAW protobuf response WITH SHOW_SLOT_ID ({len(body)} bytes)")
        print(f"{'='*70}\n")
    # GetLoginData - Response handler (BẮT RESPONSE, DECODE, SỬA FIELDS, RE-ENCODE VÀ GỬI LẠI)
    if host == "clientbp.ggpolarbear.com" and path == "/GetLoginData" and method == "POST":
        print(f"\n{'='*70}")
        print(f"🔐 GET LOGIN DATA RESPONSE (INTERCEPTED & HACKED) - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*70}")
        try:
            # 1. Lấy original response body từ server
            original_body = flow.response.content if flow.response else b""
            print(f" 📦 Original response: {len(original_body)} bytes")
            print(f" Hex preview: {original_body.hex()[:100]}...")
            # 2. Decode body sử dụng logic từ decoder script
            decoded_body = try_decode_response_body(original_body, aes_utils)
            # 3. Parse sử dụng LoginResNew_pb2 (sử dụng LoginRes thay vì LoginResNew)
            res = LoginResNew_pb2.LoginRes()
            res.ParseFromString(decoded_body)
            # 4. Debug original trước khi sửa
            print(" 🔍 Original LoginRes fields (key ones):")
            # Giả sử các fields tồn tại; in ra để debug
            try:
                print(f" - uf_9: {getattr(res, 'uf_9', 'N/A')}")
                print(f" - uf_10: {getattr(res, 'uf_10', 'N/A')}")
                print(f" - level: {getattr(res, 'level', 'N/A')}")
                print(f" - exp: {getattr(res, 'exp', 'N/A')}")
                print(f" - role: {getattr(res, 'role', 'N/A')}")
                print(f" - badge_id: {getattr(res, 'badge_id', 'N/A')}")
            except:
                debug_msg = debug_protobuf(decoded_body, "Original LoginRes")
                print(f" - uf_9: {_safe_get(debug_msg, 'uf_9', 'N/A')}")
                print(f" - uf_10: {_safe_get(debug_msg, 'uf_10', 'N/A')}")
                print(f" - level: {_safe_get(debug_msg, 'level', 'N/A')}")
                print(f" - exp: {_safe_get(debug_msg, 'exp', 'N/A')}")
                print(f" - role: {_safe_get(debug_msg, 'role', 'N/A')}")
                print(f" - badge_id: {_safe_get(debug_msg, 'badge_id', 'N/A')}")
            # 5. Sửa các fields theo yêu cầu (sử dụng setattr nếu nested hoặc direct)
            # Giả sử direct fields; nếu nested (e.g., res.user_info.uf_9), điều chỉnh tương ứng
            res.uf_9 = 100000000
            res.uf_10 = 100000000
            res.level = 1337
            res.exp = 99999999
            res.role = 16384
            res.badge_id = 1001000091
            # 6. Serialize thành binary (raw protobuf, KHÔNG MÃ HÓA - tương tự ChooseEmote)
            proto_bytes = res.SerializeToString()
            # 7. Debug sau khi sửa
            print(" 🔍 Hacked LoginRes fields:")
            print(f" - uf_9: {res.uf_9}")
            print(f" - uf_10: {res.uf_10}")
            print(f" - level: {res.level}")
            print(f" - exp: {res.exp}")
            print(f" - role: {res.role}")
            print(f" - badge_id: {res.badge_id}")
            # 8. Tạo response với modified protobuf
            body = proto_bytes
        except Exception as e:
            print(f" ❌ Error processing login response: {e}")
            import traceback
            traceback.print_exc()
            body = original_body # Fallback to original nếu lỗi
        # 9. Gửi response modified
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"\n 📤 Sent MODIFIED RAW protobuf response ({len(body)} bytes)")
        print(f"{'='*70}\n")
    # GetPlayerPersonalShow - Response handler (SỬ DỤNG MERGE LOGIC TỪ CODE MỚI, VÀ SET title_id / current_avatar TỪ STORED) - UPDATE DEBUG
    if host == "clientbp.ggpolarbear.com" and path == "/GetPlayerPersonalShow" and method == "POST":
        print(f"\n{'='*70}")
        print(f"👤 GET PLAYER PERSONAL SHOW RESPONSE (HACKED WITH MERGE & BANNER/AVATAR/CLANS) - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f" Current stored_banner_id: {stored_banner_id} | stored_avatar_id: {stored_avatar_id} | stored_clothes_id: {stored_clothes_id}")
        print(f"{'='*70}")
        try:
            # 1. Lấy original response body từ server
            original_body = flow.response.content if flow.response else b""
            print(f" 📦 Original response: {len(original_body)} bytes")
            print(f" Hex preview: {original_body.hex()[:100]}...")
            # 2. Decode original body
            decoded_original = try_decode_response_body(original_body, aes_utils)
            # 3. Parse server_msg từ decoded original
            server_msg = GetPlayerPersonalShow_pb2.GetPlayerPersonalShow()
            server_msg.ParseFromString(decoded_original)
            print(" ✅ Parsed server response with pb2")
            # 4. Load và parse từ .bin
            body = original_body  # Default fallback
            if os.path.exists(LOCAL_BIN_PATH):
                with open(LOCAL_BIN_PATH, "rb") as f:
                    bin_raw = f.read()
                print(f" 📦 Loaded .bin file: {len(bin_raw)} bytes")
                # Decode bin nếu cần
                decoded_bin = try_decode_response_body(bin_raw, aes_utils)
                local_msg = GetPlayerPersonalShow_pb2.GetPlayerPersonalShow()
                try:
                    local_msg.ParseFromString(decoded_bin)
                    print(" ✅ Parsed .bin with pb2 successfully")
                except Exception as parse_e:
                    print(f" ⚠ Failed to parse .bin with pb2: {parse_e}")
                    import traceback
                    traceback.print_exc()
                    body = decoded_original
                else:
                    # 5. Merge server_msg into local_msg (bỏ qua blocked fields)
                    merge_msg(server_msg, local_msg)
                    print(" ✅ Merged server fields into local (skipping blocked)")
                    # 6. Hard-set level nếu muốn (từ code mới)
                    updated = False
                    if local_msg.players:
                        local_msg.players[0].level = 1337
                        print(" 🔄 Hard-set players[0].level to 1337")
                        updated = True
                        # 7. Set title_id từ stored_avatar_id (từ ChooseHeadPic) - CORRECTION
                        default_title = 902037031
                        if stored_avatar_id is not None:
                            try:
                                local_msg.players[0].title_id = stored_avatar_id
                                print(f" 🔄 Set players[0].title_id to {stored_avatar_id} from ChooseHeadPic")
                                updated = True
                            except Exception as set_e:
                                print(f" ⚠ Failed to set title_id: {set_e}")
                        else:
                            local_msg.players[0].title_id = default_title
                        # 8. Set clan_id từ stored_banner_id (từ ChooseBanner) - NEW
                        default_clan = 901037021
                        if stored_banner_id is not None:
                            try:
                                local_msg.players[0].clan_id = stored_banner_id
                                print(f" 🔄 Set players[0].clan_id to {stored_banner_id} from ChooseBanner")
                                updated = True
                            except Exception as set_e:
                                print(f" ⚠ Failed to set clan_id: {set_e}")
                        else:
                            local_msg.players[0].clan_id = default_clan
                        # 9. Set current_avatar từ stored_avatar_id (giữ nguyên, hoặc adjust nếu cần)
                        if stored_avatar_id is not None:
                            try:
                                local_msg.players[0].current_avatar = stored_avatar_id
                                print(f" 🔄 Set players[0].current_avatar to {stored_avatar_id} from ChooseHeadPic")
                                updated = True
                            except Exception as set_e:
                                print(f" ⚠ Failed to set current_avatar: {set_e}")
                        else:
                            default_avatar = 902037031
                            local_msg.players[0].current_avatar = default_avatar
                        
                        print(f"\n 🏆 PROCESSING CLANS LIST (ROOT LEVEL):")
                        
                        # XỬ LÝ CLANS - NẰM Ở ROOT LEVEL
                        # Kiểm tra xem có field clans không
                        if hasattr(local_msg, 'clans'):
                            print(f"   Found 'clans' field at root level")
                            
                            # Clear existing clans
                            del local_msg.clans[:]
                            print(f"   Cleared existing clans")
                            
                            # Thêm clan mới
                            new_clan = local_msg.clans.add()
                            new_clan.clan_id = local_msg.players[0].clan_id  # Dùng clan_id từ player
                            new_clan.member_count = 50
                            print(f"   Added new clan with ID: {new_clan.clan_id}, members: 50")
                            
                            # Xử lý clan_logo
                            print(f"\n   🎨 SETTING CLAN_LOGO:")
                            
                            # Case 1: Nếu stored_clothes_hash là hex string, convert to bytes
                            if stored_clothes_hash and isinstance(stored_clothes_hash, str):
                                print(f"     clothes_hash is string (hex?): {stored_clothes_hash[:50]}...")
                                try:
                                    clan_logo_bytes = bytes.fromhex(stored_clothes_hash)
                                    new_clan.clan_logo = clan_logo_bytes
                                    print(f"     Set clan_logo from hex string to bytes")
                                except:
                                    # Fallback to default protobuf
                                    clan_logo_bytes = create_clan_logo_protobuf()
                                    new_clan.clan_logo = clan_logo_bytes
                                    print(f"     Used default clan_logo (hex parse failed)")
                            else:
                                # Case 2: No hash, tạo default
                                print(f"     No clothes_hash, creating default clan_logo")
                                clan_logo_bytes = create_clan_logo_protobuf()
                                new_clan.clan_logo = clan_logo_bytes
                            
                            print(f"     Final clan_logo bytes length: {len(new_clan.clan_logo)}")
                        else:
                            print(f"   ⚠ Root message has no 'clans' field")
                    
                    # Fallback nếu không có players, thử detailed_player
                    elif local_msg.HasField('detailed_player'):
                        local_msg.detailed_player.level = 1337
                        print(" 🔄 Hard-set detailed_player.level to 1337")
                        updated = True
                        # Set title_id từ stored_avatar_id (từ ChooseHeadPic) - CORRECTION
                        default_title = 902037031
                        if stored_avatar_id is not None:
                            try:
                                local_msg.detailed_player.title_id = stored_avatar_id
                                print(f" 🔄 Set detailed_player.title_id to {stored_avatar_id} from ChooseHeadPic")
                                updated = True
                            except Exception as set_e:
                                print(f" ⚠ Failed to set title_id: {set_e}")
                        else:
                            local_msg.detailed_player.title_id = default_title
                        # Set clan_id từ stored_banner_id (từ ChooseBanner) - NEW
                        default_clan = 901037021
                        if stored_banner_id is not None:
                            try:
                                local_msg.detailed_player.clan_id = stored_banner_id
                                print(f" 🔄 Set detailed_player.clan_id to {stored_banner_id} from ChooseBanner")
                                updated = True
                            except Exception as set_e:
                                print(f" ⚠ Failed to set clan_id: {set_e}")
                        else:
                            local_msg.detailed_player.clan_id = default_clan
                        # Set current_avatar từ stored_avatar_id (giữ nguyên)
                        if stored_avatar_id is not None:
                            try:
                                local_msg.detailed_player.current_avatar = stored_avatar_id
                                print(f" 🔄 Set detailed_player.current_avatar to {stored_avatar_id} from ChooseHeadPic")
                                updated = True
                            except Exception as set_e:
                                print(f" ⚠ Failed to set current_avatar: {set_e}")
                        else:
                            default_avatar = 902037031
                            local_msg.detailed_player.current_avatar = default_avatar
                        
                        print(f"\n 🏆 PROCESSING CLANS LIST (ROOT LEVEL):")
                        
                        # XỬ LÝ CLANS - NẰM Ở ROOT LEVEL (tương tự cho detailed_player)
                        if hasattr(local_msg, 'clans'):
                            print(f"   Found 'clans' field at root level")
                            
                            # Clear existing clans
                            del local_msg.clans[:]
                            print(f"   Cleared existing clans")
                            
                            # Thêm clan mới
                            new_clan = local_msg.clans.add()
                            new_clan.clan_id = local_msg.detailed_player.clan_id  # Dùng clan_id từ detailed_player
                            new_clan.member_count = 50
                            print(f"   Added new clan with ID: {new_clan.clan_id}, members: 50")
                            
                            # Xử lý clan_logo (tương tự)
                            print(f"\n   🎨 SETTING CLAN_LOGO:")
                            
                            if stored_clothes_hash and isinstance(stored_clothes_hash, str):
                                print(f"     clothes_hash is string (hex?): {stored_clothes_hash[:50]}...")
                                try:
                                    clan_logo_bytes = bytes.fromhex(stored_clothes_hash)
                                    new_clan.clan_logo = clan_logo_bytes
                                    print(f"     Set clan_logo from hex string to bytes")
                                except:
                                    clan_logo_bytes = create_clan_logo_protobuf()
                                    new_clan.clan_logo = clan_logo_bytes
                                    print(f"     Used default clan_logo (hex parse failed)")
                            else:
                                print(f"     No clothes_hash, creating default clan_logo")
                                clan_logo_bytes = create_clan_logo_protobuf()
                                new_clan.clan_logo = clan_logo_bytes
                            
                            print(f"     Final clan_logo bytes length: {len(new_clan.clan_logo)}")
                        else:
                            print(f"   ⚠ Root message has no 'clans' field")
                    
                    if updated:
                        print(" ✅ Updated with title/clan/current_avatar from requests")
                    print(f"\n ✅ Finished updating player data and clans")
                    # 10. Serialize modified local_msg
                    body = local_msg.SerializeToString()
                    print(f" ✅ Modified .bin with merged server data + hard-set level + title/clan/avatar + clans injection")
            else:
                print(" ⚠ GetPlayerPersonalShow.bin not found, fallback to decoded original")
                body = decoded_original
            # 11. Debug modified nếu cần
            print(f"\n 🔍 Final modified message debug (blackbox):")
            try:
                # Lấy message từ tuple (msg, typedef)
                msg, typedef = blackboxprotobuf.decode_message(body)
                
                # Tìm clans trong decoded message
                print(f"   All fields in message:")
                for key, value in sorted(msg.items()):
                    key_type = type(key).__name__
                    if isinstance(value, list):
                        print(f"     {key_type} {key}: LIST with {len(value)} items")
                        # Kiểm tra nếu là clans list
                        for i, item in enumerate(value):
                            if isinstance(item, dict):
                                print(f"       Item {i}:")
                                for sub_key, sub_val in item.items():
                                    if isinstance(sub_val, bytes):
                                        print(f"         {sub_key}: bytes (len={len(sub_val)})")
                                        # Thử decode clan_logo nếu có
                                        if sub_key in ['clan_logo', 3, '3']:  # clan_logo thường là field 3
                                            try:
                                                decoded_logo = blackboxprotobuf.decode_message(sub_val)
                                                print(f"           Decoded clan_logo: {decoded_logo[0]}")
                                            except:
                                                print(f"           Hex: {sub_val.hex()[:50]}...")
                                    else:
                                        print(f"         {sub_key}: {sub_val}")
                    elif isinstance(value, bytes):
                        print(f"     {key_type} {key}: bytes (len={len(value)})")
                    else:
                        print(f"     {key_type} {key}: {value}")
                        
            except Exception as debug_e:
                print(f"   ⚠ Debug error: {debug_e}")
                import traceback
                traceback.print_exc()
        except Exception as e:
            print(f" ❌ Error processing GetPlayerPersonalShow response: {e}")
            import traceback
            traceback.print_exc()
            body = original_body  # Fallback to original nếu lỗi
        # 12. Gửi response modified
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"\n 📤 Sent MODIFIED protobuf response ({len(body)} bytes)")
        print(f"{'='*70}\n")
    # Các endpoint khác (giữ nguyên logic cũ)
    if host == "clientbp.ggpolarbear.com" and path == "/GetBackpack" and method == "POST":
        print(f"\n📦 GetBackpack - {datetime.datetime.now().strftime('%H:%M:%S')}")
        try:
            if os.path.exists("GetBackpack.bin"):
                with open("GetBackpack.bin", "rb") as f:
                    body = f.read()
                print(f" Loaded {len(body)} bytes")
            else:
                print(" File not found, sending empty response")
                body = b""
        except Exception as e:
            print(f" ❌ Error: {e}")
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
    if host == "clientbp.ggpolarbear.com" and path == "/GetPrimeAccountInfo" and method == "POST":
        print(f"\n👑 GetPrimeAccountInfo - {datetime.datetime.now().strftime('%H:%M:%S')}")
        try:
            if os.path.exists("GetPrimeAccountInfo.bin"):
                with open("GetPrimeAccountInfo.bin", "rb") as f:
                    body = f.read()
                print(f" Loaded {len(body)} bytes")
            else:
                print(" File not found, sending empty response")
                body = b""
        except Exception as e:
            print(f" ❌ Error: {e}")
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
    if host == "clientbp.ggpolarbear.com" and path == "/GetVipCardInfo" and method == "POST":
        print(f"\n💎 GetVipCardInfo - {datetime.datetime.now().strftime('%H:%M:%S')}")
        try:
            if os.path.exists("GetVipCardInfo.bin"):
                with open("GetVipCardInfo.bin", "rb") as f:
                    body = f.read()
                print(f" Loaded {len(body)} bytes")
            else:
                print(" File not found, sending empty response")
                body = b""
        except Exception as e:
            print(f" ❌ Error: {e}")
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
    if host == "clientbp.ggpolarbear.com" and path == "/GetUnlockedFittingSlots" and method == "POST":
        print(f"\n🔓 GetUnlockedFittingSlots - {datetime.datetime.now().strftime('%H:%M:%S')}")
        try:
            if os.path.exists("GetUnlockedFittingSlots.bin"):
                with open("GetUnlockedFittingSlots.bin", "rb") as f:
                    body = f.read()
                print(f" Loaded {len(body)} bytes")
            else:
                print(" File not found, sending empty response")
                body = b""
        except Exception as e:
            print(f" ❌ Error: {e}")
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
    if host == "clientbp.ggpolarbear.com" and path == "/UnlockProfile" and method == "POST":
        print(f"\n🔓 UnlockProfile - 200 OK - {datetime.datetime.now().strftime('%H:%M:%S')}")
        flow.response = http.Response.make(200, b"", _make_headers(b""))
    if host == "clientbp.ggpolarbear.com" and path == "/SetAccountBadge" and method == "POST":
        print(f"\n🔓 SetAccountBadge - 200 OK - {datetime.datetime.now().strftime('%H:%M:%S')}")
        flow.response = http.Response.make(200, b"", _make_headers(b""))
    if host == "clientbp.ggpolarbear.com" and path == "/UsePlayItemLimitedCards" and method == "POST":
        print(f"\n🎴 UsePlayItemLimitedCards - 200 OK - {datetime.datetime.now().strftime('%H:%M:%S')}")
        flow.response = http.Response.make(200, b"", _make_headers(b""))

# Thêm load function cho mitmproxy
def load(loader):
    print("🚀 MitmProxy Handler Loaded!")
    # Không load storage nữa - chỉ in-memory, defaults là None/empty

if __name__ == "__main__":
    print("\n✅ Script ready! Run with: mitmweb -s mitmweb_handlers.py")