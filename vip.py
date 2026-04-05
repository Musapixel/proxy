from mitmproxy import http
import GetPlayerPersonalShow_pb2
import blackboxprotobuf
from google.protobuf.descriptor import FieldDescriptor

LOCAL_BIN_PATH = "GetPlayerPersonalShow.bin"
LOCAL_RANKING_BIN = "GetPlayerRankingInfo.bin"

LAST_USER_ID = None

BLOCK_FIELDS = {
    "field_65",
    "cosmetic_skin",
    "kills",
    "field_76",
    "field_75",
    "matches_played",
    "field_48"
}

# -----------------------------
# Merge protobuf pb2
# -----------------------------
def merge_msg(src, dst):
    for field in src.DESCRIPTOR.fields:

        if field.name in BLOCK_FIELDS:
            continue

        val = getattr(src, field.name)

        if field.label == FieldDescriptor.LABEL_REPEATED:

            dst_list = getattr(dst, field.name)

            if field.type == FieldDescriptor.TYPE_MESSAGE:
                while len(dst_list) < len(val):
                    dst_list.add()

                for i in range(len(val)):
                    merge_msg(val[i], dst_list[i])

            else:
                dst_list[:] = val

        else:
            if field.type == FieldDescriptor.TYPE_MESSAGE:
                merge_msg(val, getattr(dst, field.name))
            else:
                setattr(dst, field.name, val)


# -----------------------------
# Decode / Encode blackboxprotobuf
# -----------------------------
def parse_pb(data):
    return blackboxprotobuf.decode_message(data)

def serialize_pb(msg, typedef):
    return blackboxprotobuf.encode_message(msg, typedef)


# -----------------------------
# MAIN MITM HANDLER
# -----------------------------
def response(flow: http.HTTPFlow):
    try:
        host = flow.request.host
        path = flow.request.path
        method = flow.request.method

        # =============================================================
        # 1. GET PLAYER PERSONAL SHOW → LẤY USER_ID
        # =============================================================
        if "/GetPlayerPersonalShow" in path:
            print("\n===== INTERCEPT /GetPlayerPersonalShow =====")

            server_msg = GetPlayerPersonalShow_pb2.GetPlayerPersonalShow()
            server_msg.ParseFromString(flow.response.content)

            local_msg = GetPlayerPersonalShow_pb2.GetPlayerPersonalShow()
            with open(LOCAL_BIN_PATH, "rb") as f:
                local_msg.ParseFromString(f.read())

            merge_msg(server_msg, local_msg)

            global LAST_USER_ID
            if local_msg.players:
                LAST_USER_ID = local_msg.players[0].user_id
                print("✓ Stored user_id =", LAST_USER_ID)

            out = local_msg.SerializeToString()

            flow.response = http.Response.make(
                200,
                out,
                {"Content-Type": "application/octet-stream"}
            )
            return

        # =============================================================
        # 2. GET PLAYER RANKING INFO → MERGE + INJECT USER ID
        # =============================================================
        if "/GetPlayerRankingInfo" in path:
            print("\n===== INTERCEPT /GetPlayerRankingInfo =====")

            server_msg, server_td = parse_pb(flow.response.content)

            with open(LOCAL_RANKING_BIN, "rb") as f:
                local_msg, local_td = parse_pb(f.read())

            # merge đơn giản kiểu dict
            local_msg.update(server_msg)

            # inject user_id
            if LAST_USER_ID is not None:
                local_msg["1"] = LAST_USER_ID
                print("✓ Inject user_id ->", LAST_USER_ID)

            out = serialize_pb(local_msg, local_td)  # đã là bytes

            flow.response = http.Response.make(
                200,
                out,
                {"Content-Type": "application/octet-stream"}
            )
            return

        # =============================================================
        # 3. GetPlayerRecentMaxRank → TRẢ VỀ FILE BIN (KHÔNG BAO GIỜ LỖI)
        # =============================================================
        if host == "clientbp.ggpolarbear.com" and path == "/GetPlayerRecentMaxRank" and method == "POST":
            print("\n===== GET PLAYER RECENT MAX RANK =====")

            try:
                with open("data/player_recent_max_rank.bin", "rb") as f:
                    raw = f.read()

                # ÉP VỀ bytes DÙ CÓ RA bytearray
                bin_data = bytes(raw)

            except Exception as e:
                print("LỖI ĐỌC FILE:", e)
                bin_data = b""

            flow.response = http.Response.make(
                200,
                bin_data,
                {
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(len(bin_data))
                }
            )
            return


    except Exception as e:
        print("❌ ERROR:", e)
        import traceback
        traceback.print_exc()
