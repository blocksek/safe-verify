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
        abi = json.loads(resp["result"])
        
        # Check if this is a proxy contract (only has constructor/fallback)
        function_count = sum(1 for entry in abi if entry.get("type") == "function")
        if function_count == 0:
            # Try to get implementation address for proxy contracts
            impl_address = get_implementation_address(address, chainid)
            if impl_address:
                return fetch_abi(impl_address, chainid)
        
        return abi
    raise ValueError(f"ABI not available for {address}")

def get_implementation_address(proxy_address: str, chainid: int = 1) -> str:
    """Try to get implementation address from proxy contract"""
    # Common proxy implementation slots
    slots = [
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",  # EIP-1967
        "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",  # OpenZeppelin
    ]
    
    for slot in slots:
        try:
            url = (
                f"{BASE_URL}?chainid={chainid}&module=proxy&action=eth_getStorageAt"
                f"&address={proxy_address}&position={slot}&tag=latest&apikey={API_KEY}"
            )
            resp = requests.get(url, timeout=10).json()
            if resp.get("result") and resp["result"] != "0x0000000000000000000000000000000000000000000000000000000000000000":
                # Extract address from storage slot (last 20 bytes)
                impl_addr = "0x" + resp["result"][-40:]
                if impl_addr != "0x0000000000000000000000000000000000000000":
                    return Web3.to_checksum_address(impl_addr)
        except Exception:
            continue
    
    return None

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

# Common function signatures for fallback
COMMON_SIGNATURES = {
    "0xe318b52b": {"name": "swapOwner", "inputs": ["address", "address", "address"]},
    "0x0d582f13": {"name": "addOwnerWithThreshold", "inputs": ["address", "uint256"]},
    "0xac9650d8": {"name": "multicall", "inputs": ["bytes[]"]},
    "0x6a761202": {"name": "execTransaction", "inputs": ["address", "uint256", "bytes", "uint8", "uint256", "uint256", "uint256", "address", "address", "bytes"]},
}

def decode_nested_data(data: str, chainid: int = 1) -> Dict:
    """Recursively decode nested transaction data"""
    if len(data) < 10:
        return {"raw": data}
    
    sig = data[:10]
    if sig in COMMON_SIGNATURES:
        func_info = COMMON_SIGNATURES[sig]
        try:
            raw_args = decode_abi(func_info["inputs"], bytes.fromhex(data[10:]))
            args = []
            for i, arg in enumerate(raw_args):
                if isinstance(arg, (bytes, bytearray)):
                    hex_arg = "0x" + arg.hex()
                    # Try to decode if it looks like function call data
                    if len(hex_arg) >= 10 and hex_arg.startswith("0x"):
                        nested = decode_nested_data(hex_arg, chainid)
                        args.append({"value": hex_arg, "decoded": nested})
                    else:
                        args.append(hex_arg)
                else:
                    args.append(arg)
            
            return {
                "method": func_info["name"],
                "args": args,
                "signature": sig
            }
        except Exception:
            pass
    
    return {"raw": data, "signature": sig}

# ---------- abi-aware --------------------------------------------------------
def enrich(tx: Dict, chainid: int = 1) -> Dict:
    try:
        abi   = fetch_abi(tx["to"], chainid)
        sig   = tx["data"][:10]
        entry = next(e for e in abi if e.get("type")=="function" and
                     "0x"+sig_from_abi(e) == sig)
        arg_t = [i["type"] for i in entry["inputs"]]
        raw_args = decode_abi(arg_t, bytes.fromhex(tx["data"][10:]))
        args = []
        for i, arg in enumerate(raw_args):
            if isinstance(arg, (bytes, bytearray)):
                hex_arg = "0x" + arg.hex()
                # Try to decode if it looks like function call data
                if len(hex_arg) >= 10:
                    nested = decode_nested_data(hex_arg, chainid)
                    args.append({"value": hex_arg, "decoded": nested})
                else:
                    args.append(hex_arg)
            else:
                args.append(arg)
        
        return {**tx, "method": entry["name"], "args": args, "decoded_data": decode_nested_data(tx["data"], chainid)}
    except Exception as e:
        # Fallback to common signatures
        sig = tx["data"][:10]
        if sig in COMMON_SIGNATURES:
            func_info = COMMON_SIGNATURES[sig]
            try:
                raw_args = decode_abi(func_info["inputs"], bytes.fromhex(tx["data"][10:]))
                args = []
                for i, arg in enumerate(raw_args):
                    if isinstance(arg, (bytes, bytearray)):
                        hex_arg = "0x" + arg.hex()
                        # Try to decode if it looks like function call data
                        if len(hex_arg) >= 10:
                            nested = decode_nested_data(hex_arg, chainid)
                            args.append({"value": hex_arg, "decoded": nested})
                        else:
                            args.append(hex_arg)
                    else:
                        args.append(arg)
                
                return {**tx, "method": func_info["name"], "args": args, "decoded_data": decode_nested_data(tx["data"], chainid)}
            except Exception as decode_error:
                return {**tx, "method": func_info["name"], "args": [], "error": str(decode_error), "decoded_data": decode_nested_data(tx["data"], chainid)}
        
        return {**tx, "method": "UNKNOWN", "args": [], "error": str(e), "decoded_data": decode_nested_data(tx["data"], chainid)}

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

