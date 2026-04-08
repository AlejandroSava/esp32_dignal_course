import os
import base64
import binascii
import hmac
import hashlib
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ============================================================
# Configuration
# ============================================================

SERVER_NAME = "IoT_Server"
HTTP_ADDRESS = "http://192.168.1.236:5000/example"

PK_PATH = "/home/alejandro/my_kyber_example/pk.bin"
CT_PATH = "/home/alejandro/my_kyber_example/ct.bin"
DECRYPT_BIN = "/home/alejandro/my_kyber_example/3_decrypt"
KEY_A_PATH = "/home/alejandro/my_kyber_example/key_a.bin"

SID_SIZE = 16
NONCE_S_SIZE = 32
KAUTH_SIZE = 32
KSESS_SIZE = 32
TAG_SIZE = 64  # HMAC-SHA512 output size


# ============================================================
# Crypto helpers
# ============================================================

def hkdf_sha512(ikm: bytes, salt: bytes, info: str, length: int) -> bytes:
    if not ikm:
        raise ValueError("IKM must not be empty")
    if not salt:
        raise ValueError("Salt must not be empty")
    if info is None:
        raise ValueError("Info must not be None")
    if length <= 0:
        raise ValueError("Length must be greater than 0")

    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=salt,
        info=info.encode("utf-8"),
    )
    return hkdf.derive(ikm)


def hmac_sha512(key: bytes, *parts: bytes) -> bytes:
    if not key:
        raise ValueError("HMAC key must not be empty")

    mac = hmac.new(key, digestmod=hashlib.sha512)
    for part in parts:
        if part is None:
            raise ValueError("HMAC input part must not be None")
        mac.update(part)
    return mac.digest()


# ============================================================
# Encoding helpers
# ============================================================

def b64encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode_bytes(value: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"{field_name} is not valid base64: {e}") from e


def make_error(step: Optional[int], message: str, status_code: int = 400):
    payload = {
        "Status": "Fail",
        "Error": message
    }
    if step is not None:
        payload["Step"] = step
    return jsonify(payload), status_code


# ============================================================
# Data models
# ============================================================

@dataclass
class DeviceRecord:
    device_name: str
    mac_address: bytes
    puf_hash: bytes


@dataclass
class SessionRecord:
    sid: bytes
    sid_b64: str
    device_name: str
    nonce_s: bytes
    nonce_s_b64: str
    kauth: Optional[bytes] = None
    ksess: Optional[bytes] = None
    shared_secret: Optional[bytes] = None


# ============================================================
# Flask app
# ============================================================

app = Flask(__name__)

devices: dict[str, DeviceRecord] = {}
sessions: dict[str, SessionRecord] = {}


# ============================================================
# Main endpoint
# ============================================================

@app.route("/example", methods=["GET", "POST"])
def example():
    print("Entry to /example endpoint")

    if request.method == "GET":
        pk_file = Path(PK_PATH)
        if not pk_file.exists():
            return make_error(None, "Kyber public key file not found", 404)

        pk = pk_file.read_bytes()
        return jsonify({
            "Step": 0,
            "Server_Name": SERVER_NAME,
            "Kyber_Pk_Len": len(pk),
            "Kyber_Pk": b64encode_bytes(pk),
        }), 200

    data = request.get_json(silent=True)
    print("Incoming JSON:", data)

    if not data:
        return make_error(None, "Invalid JSON body", 400)

    step = data.get("Step")
    if not isinstance(step, int):
        return make_error(None, "Missing or invalid Step field", 400)

    try:
        # ========================================================
        # STEP 0
        #
        # Request:
        # {
        #   "Step": 0,
        #   "Device_Name": "...",
        #   "Mac_Address": "...",
        #   "PUF_Hash": "..."
        # }
        #
        # Response:
        # {
        #   "Step": 0,
        #   "Server_Name": "IoT_Server",
        #   "Kyber_Pk_Len": ...,
        #   "Kyber_Pk": "..."
        # }
        # ========================================================
        if step == 0:
            device_name = data.get("Device_Name")
            mac_address_b64 = data.get("Mac_Address")
            puf_hash_b64 = data.get("PUF_Hash")

            if not device_name or not mac_address_b64 or not puf_hash_b64:
                return make_error(
                    step,
                    "Missing Device_Name, Mac_Address, or PUF_Hash",
                    400
                )

            mac_address = b64decode_bytes(mac_address_b64, "Mac_Address")
            puf_hash = b64decode_bytes(puf_hash_b64, "PUF_Hash")

            devices[device_name] = DeviceRecord(
                device_name=device_name,
                mac_address=mac_address,
                puf_hash=puf_hash
            )

            pk_file = Path(PK_PATH)
            if not pk_file.exists():
                return make_error(step, "Kyber public key file not found", 500)

            pk = pk_file.read_bytes()

            print("STEP 0")
            print("  Device_Name :", device_name)
            print("  Mac_Address :", mac_address.hex())
            print("  PUF_Hash    :", puf_hash.hex())

            response = {
                "Step": 0,
                "Server_Name": SERVER_NAME,
                "Kyber_Pk_Len": len(pk),
                "Kyber_Pk": b64encode_bytes(pk),
            }
            return jsonify(response), 200

        # ========================================================
        # STEP 1
        #
        # Request:
        # {
        #   "Step": 1,
        #   "Device_Name": "..."
        # }
        #
        # Response:
        # {
        #   "Step": 1,
        #   "Server_Name": "IoT_Server",
        #   "SID_Len": 16,
        #   "SID": "...",
        #   "Nonce_S_Len": 32,
        #   "Nonce_S": "..."
        # }
        # ========================================================
        if step == 1:
            device_name = data.get("Device_Name")

            if not device_name:
                return make_error(step, "Missing Device_Name", 400)

            if device_name not in devices:
                return make_error(
                    step,
                    "Unknown device. Step 0 must be completed first",
                    400
                )

            sid = os.urandom(SID_SIZE)
            nonce_s = os.urandom(NONCE_S_SIZE)

            sid_b64 = b64encode_bytes(sid)
            nonce_s_b64 = b64encode_bytes(nonce_s)

            sessions[sid_b64] = SessionRecord(
                sid=sid,
                sid_b64=sid_b64,
                device_name=device_name,
                nonce_s=nonce_s,
                nonce_s_b64=nonce_s_b64
            )

            print("STEP 1")
            print("  Device_Name :", device_name)
            print("  SID         :", sid.hex())
            print("  Nonce_S     :", nonce_s.hex())

            response = {
                "Step": 1,
                "Server_Name": SERVER_NAME,
                "SID_Len": len(sid),
                "SID": sid_b64,
                "Nonce_S_Len": len(nonce_s),
                "Nonce_S": nonce_s_b64,
            }
            return jsonify(response), 200

        # ========================================================
        # STEP 2
        #
        # Request:
        # {
        #   "Step": 2,
        #   "SID_Len": ...,
        #   "SID": "...",
        #   "Nonce_D_Len": ...,
        #   "Nonce_D": "...",
        #   "CT_Kyber_Len": ...,
        #   "CT_Kyber": "...",
        #   "Tag_D_Len": 64,
        #   "Tag_D": "..."
        # }
        #
        # TagD =
        #   HMAC-SHA512(Kauth,
        #               SID || nonce_s || nonce_d || PK || CT || device_name)
        #
        # Kauth =
        #   HKDF-SHA512(PUF_Hash, Nonce_S, "Kauth", 32)
        #
        # Ksess =
        #   HKDF-SHA512(SS, Nonce_S, "Ksess", 32)
        #
        # TagS =
        #   HMAC-SHA512(Ksess, SID || nonce_s || nonce_d)
        # ========================================================
        if step == 2:
            sid_b64 = data.get("SID")
            sid_len = data.get("SID_Len")
            nonce_d_b64 = data.get("Nonce_D")
            nonce_d_len = data.get("Nonce_D_Len")
            ct_b64 = data.get("CT_Kyber")
            ct_len = data.get("CT_Kyber_Len")
            tag_d_b64 = data.get("Tag_D")
            tag_d_len = data.get("Tag_D_Len")

            if (sid_b64 is None or sid_len is None or
                    nonce_d_b64 is None or nonce_d_len is None or
                    ct_b64 is None or ct_len is None or
                    tag_d_b64 is None or tag_d_len is None):
                return make_error(
                    step,
                    "Missing one or more required Step 2 fields",
                    400
                )

            session = sessions.get(sid_b64)
            if session is None:
                return make_error(step, "Invalid SID", 400)

            device = devices.get(session.device_name)
            if device is None:
                return make_error(step, "Device record not found", 400)

            sid = b64decode_bytes(sid_b64, "SID")
            nonce_d = b64decode_bytes(nonce_d_b64, "Nonce_D")
            ct = b64decode_bytes(ct_b64, "CT_Kyber")
            tag_d = b64decode_bytes(tag_d_b64, "Tag_D")

            if len(sid) != sid_len:
                return make_error(step, "SID_Len does not match decoded SID length", 400)

            if len(nonce_d) != nonce_d_len:
                return make_error(step, "Nonce_D_Len does not match decoded Nonce_D length", 400)

            if len(ct) != ct_len:
                return make_error(step, "CT_Kyber_Len does not match decoded CT_Kyber length", 400)

            if len(tag_d) != tag_d_len:
                return make_error(step, "Tag_D_Len does not match decoded Tag_D length", 400)

            if sid != session.sid:
                return make_error(step, "SID content does not match session", 400)

            if len(tag_d) != TAG_SIZE:
                return make_error(step, f"Tag_D must be {TAG_SIZE} bytes", 400)

            pk_file = Path(PK_PATH)
            if not pk_file.exists():
                return make_error(step, "Kyber public key file not found", 500)

            pk = pk_file.read_bytes()
            device_name_bytes = session.device_name.encode("utf-8")

            # Kauth = HKDF-SHA512(PUF_Hash, Nonce_D, "Kauth", 32)
            kauth = hkdf_sha512(
                ikm=device.puf_hash,
                salt=session.nonce_s,
                info="Kauth",
                length=KAUTH_SIZE
            )
            session.kauth = kauth

            # TagD = HMAC-SHA512(Kauth, SID || nonce_s || nonce_d || PK || CT || device_name)
            expected_tag_d = hmac_sha512(
                kauth,
                sid,
                session.nonce_s,
                nonce_d,
                pk,
                ct,
                device_name_bytes
            )

            if not hmac.compare_digest(tag_d, expected_tag_d):
                print("STEP 2")
                print("  Tag_D verification failed")
                print("  Received Tag_D :", tag_d.hex())
                print("  Expected Tag_D :", expected_tag_d.hex())
                return make_error(step, "Tag_D verification failed", 401)

            print("STEP 2")
            print("  SID           :", sid.hex())
            print("  Nonce_S       :", session.nonce_s.hex())
            print("  Nonce_D       :", nonce_d.hex())
            print("  Kauth         :", kauth.hex())
            print("  Tag_D OK      :", tag_d.hex())

            with open(CT_PATH, "wb") as f:
                f.write(ct)

            result = subprocess.run(
                [DECRYPT_BIN],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print("Decrypt stdout:", result.stdout)
                print("Decrypt stderr:", result.stderr)
                return make_error(step, "Decrypt process failed", 500)

            ss_file = Path(KEY_A_PATH)
            if not ss_file.exists():
                return make_error(step, "Shared secret file not found", 500)

            shared_secret = ss_file.read_bytes()
            session.shared_secret = shared_secret

            # Ksess = HKDF-SHA512(SS, Nonce_S, "Ksess", 32)
            ksess = hkdf_sha512(
                ikm=shared_secret,
                salt=session.nonce_s,
                info="Ksess",
                length=KSESS_SIZE
            )
            session.ksess = ksess

            # TagS = HMAC-SHA512(Ksess, SID || nonce_s || nonce_d)
            tag_s = hmac_sha512(
                ksess,
                sid,
                session.nonce_s,
                nonce_d
            )

            print("  Shared Secret :", shared_secret.hex())
            print("  Ksess         :", ksess.hex())
            print("  Tag_S         :", tag_s.hex())

            response = {
                "Step": 2,
                "SID_Len": len(sid),
                "SID": sid_b64,
                "Tag_S_Len": len(tag_s),
                "Tag_S": b64encode_bytes(tag_s),
            }
            return jsonify(response), 200

        return make_error(step, "Invalid step", 400)

    except ValueError as e:
        print("ValueError:", str(e))
        return make_error(step, str(e), 400)
    except Exception as e:
        print("Exception:", str(e))
        return make_error(step, f"Internal server error: {e}", 500)


if __name__ == "__main__":
    print("Starting AKE Flask server...")
    app.run(host="192.168.1.236", port=5000, debug=True)

