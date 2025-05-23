import os, json, requests
from functools import lru_cache
from typing import List, Dict
from eth_abi.abi import decode as decode_abi
from web3 import Web3

API_KEY = os.getenv("ETHERSCAN_API_KEY")
if not API_KEY:
    raise EnvironmentError("Missing ETHERSCAN_API_KEY environment variable")

# base endpoint for the multi-chain etherscan API
BASE_URL = "https://api.etherscan.io/api"
w3 = Web3()

# ---------- helpers ----------------------------------------------------------
@lru_cache(maxsize=None)
def fetch_abi(address: str, chainid: int = 1) -> list:
    url = (
        f"{BASE_URL}?chainid={chainid}&module=contract&action=getabi"
        f"&address={address}&apikey={API_KEY}"
    )
    resp = requests.get(url, timeout=10).json()
    if resp.get("status") == "1":  # verified contract
        return json.loads(resp["result"])
    raise ValueError(f"ABI not available for {address}")

def sig_from_abi(entry):
    types = ",".join(i["type"] for i in entry["inputs"])
    return w3.keccak(text=f"{entry['name']}({types})")[:4].hex()

# ---------- multisend  -------------------------------------------------------
def decode_multisend(raw_hex: str) -> List[Dict]:
    raw_hex = raw_hex.removeprefix("0x")
    blob, i, out = bytes.fromhex(raw_hex), 0, []
    while i < len(blob):
        op      = blob[i]                  ; i += 1
        to      = Web3.to_checksum_address(blob[i:i+20].hex()) ; i += 20
        value   = int.from_bytes(blob[i:i+32], "big")          ; i += 32
        dlen    = int.from_bytes(blob[i:i+32], "big")          ; i += 32
        data    = blob[i:i+dlen]           ; i += dlen
        out.append({"operation": op, "to": to, "value": value,
                    "data": "0x" + data.hex()})
    return out

# ---------- abi-aware --------------------------------------------------------
def enrich(tx: Dict, chainid: int = 1) -> Dict:
    try:
        abi   = fetch_abi(tx["to"], chainid)
        sig   = tx["data"][:10]
        entry = next(e for e in abi if e.get("type")=="function" and
                     "0x"+sig_from_abi(e) == sig)
        arg_t = [i["type"] for i in entry["inputs"]]
        raw_args = decode_abi(arg_t, bytes.fromhex(tx["data"][10:]))
        args = [
            ("0x" + a.hex()) if isinstance(a, (bytes, bytearray)) else a
            for a in raw_args
        ]
        return {**tx, "method": entry["name"], "args": args}
    except Exception as e:
        return {**tx, "method": "UNKNOWN", "args": [], "error": str(e)}

# ---------- CLI --------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Decode a Safe multisend transaction blob"
    )
    parser.add_argument(
        "blob",
        help="Hex encoded multisend transaction data",
    )
    parser.add_argument(
        "--chainid",
        type=int,
        default=1,
        help="Chain ID used for ABI lookups (default: 1 for Ethereum mainnet)",
    )
    args = parser.parse_args()

    decoded = [enrich(t, args.chainid) for t in decode_multisend(args.blob)]
    print(json.dumps(decoded, indent=2))

