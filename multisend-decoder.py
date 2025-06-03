import os, json, requests, sys, time
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
        f"{BASE_URL}?module=contract&action=getabi"
        f"&address={address}&apikey={API_KEY}"
    )
    time.sleep(0.25)  # Rate limit: 4 calls per second
    resp = requests.get(url, timeout=10).json()
    if resp.get("status") == "1":  # verified contract
        abi = json.loads(resp["result"])
        
        
        # Check if this is a proxy contract
        # 1. Check if it has zero functions (minimal proxy)
        function_count = sum(1 for entry in abi if entry.get("type") == "function")
        
        # 2. Check if it's an ERC1967Proxy by looking for specific proxy functions
        function_names = {entry.get("name") for entry in abi if entry.get("type") == "function"}
        is_erc1967_proxy = (
            function_count <= 5 and  # ERC1967Proxy typically has very few functions
            any(name in function_names for name in ["upgradeTo", "upgradeToAndCall"]) or
            "implementation" in function_names or
            function_count == 0
        )
        
        if is_erc1967_proxy:
            # Try to get implementation address for proxy contracts
            impl_address = get_implementation_address(address, chainid)
            if impl_address:
                return fetch_abi(impl_address, chainid)
        
        return abi
    raise ValueError(f"ABI not available for {address}")

def get_implementation_address(proxy_address: str, chainid: int = 1) -> str:
    """Try to get implementation address from proxy contract"""
    
    # First try calling implementation() function directly (for ERC1967 proxies)
    try:
        # implementation() function selector is 0x5c60da1b
        url = (
            f"{BASE_URL}?module=proxy&action=eth_call"
            f"&to={proxy_address}&data=0x5c60da1b&tag=latest&apikey={API_KEY}"
        )
        time.sleep(0.25)  # Rate limit: 4 calls per second
        resp = requests.get(url, timeout=10).json()
        if resp.get("result") and resp["result"] != "0x":
            impl_addr = "0x" + resp["result"][-40:]
            if impl_addr != "0x0000000000000000000000000000000000000000":
                return Web3.to_checksum_address(impl_addr)
    except Exception:
        pass
    
    # Fallback to storage slot reading
    slots = [
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",  # EIP-1967 implementation slot
        "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",  # OpenZeppelin Proxy
        "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7",  # EIP-1822 UUPS
        "0x5ca1e165638df959c89e32c68fbe603b40e3797aa62bebc0d1b0db88e42d0e3a",  # Custom implementation slot
    ]
    
    for slot in slots:
        try:
            url = (
                f"{BASE_URL}?module=proxy&action=eth_getStorageAt"
                f"&address={proxy_address}&position={slot}&tag=latest&apikey={API_KEY}"
            )
            time.sleep(0.25)  # Rate limit: 4 calls per second
            resp = requests.get(url, timeout=10).json()
            if resp.get("result") and resp["result"] != "0x0000000000000000000000000000000000000000000000000000000000000000":
                # Extract address from storage slot (last 20 bytes)
                impl_addr = "0x" + resp["result"][-40:]
                if impl_addr != "0x0000000000000000000000000000000000000000":
                    return Web3.to_checksum_address(impl_addr)
        except Exception:
            continue
    
    return None

def expand_tuple_type(input_type, components):
    """Expand tuple type to its canonical form"""
    if input_type == "tuple":
        component_types = []
        for component in components:
            if component["type"] == "tuple":
                expanded = expand_tuple_type(component["type"], component.get("components", []))
                component_types.append(expanded)
            else:
                component_types.append(component["type"])
        return f"({','.join(component_types)})"
    else:
        return input_type

def sig_from_abi(entry):
    canonical_types = []
    for input_param in entry["inputs"]:
        if input_param["type"] == "tuple":
            canonical_type = expand_tuple_type(input_param["type"], input_param.get("components", []))
            canonical_types.append(canonical_type)
        else:
            canonical_types.append(input_param["type"])
    
    types_str = ",".join(canonical_types)
    full_sig = f"{entry['name']}({types_str})"
    calculated_sig = w3.keccak(text=full_sig)[:4].hex()
    
    
    return calculated_sig

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

# Common function signatures for fallback - now empty, relies on ABI-based signature calculation
COMMON_SIGNATURES = {}

def decode_nested_data(data: str, chainid: int = 1) -> Dict:
    """Recursively decode nested transaction data"""
    if len(data) < 10:
        return {"raw": data}
    
    sig = data[:10]
    return {"raw": data, "signature": sig}

# ---------- abi-aware --------------------------------------------------------
def enrich(tx: Dict, chainid: int = 1) -> Dict:
    try:
        abi   = fetch_abi(tx["to"], chainid)
        sig   = tx["data"][:10]
        entry = next(e for e in abi if e.get("type")=="function" and
                     "0x"+sig_from_abi(e) == sig)
        
        # Convert ABI types to canonical types for decoding
        canonical_types = []
        for input_param in entry["inputs"]:
            if input_param["type"] == "tuple":
                canonical_type = expand_tuple_type(input_param["type"], input_param.get("components", []))
                canonical_types.append(canonical_type)
            else:
                canonical_types.append(input_param["type"])
        
        def convert_bytes_to_hex(obj):
            """Recursively convert bytes objects to hex strings for JSON serialization"""
            if isinstance(obj, (bytes, bytearray)):
                return "0x" + obj.hex()
            elif isinstance(obj, tuple):
                return [convert_bytes_to_hex(item) for item in obj]
            elif isinstance(obj, list):
                return [convert_bytes_to_hex(item) for item in obj]
            else:
                return obj
        
        def convert_tuple_to_dict(arg, components):
            """Convert tuple to dictionary with field names from ABI components"""
            if not components or len(components) != len(arg):
                return convert_bytes_to_hex(list(arg))
            
            result = {}
            for i, component in enumerate(components):
                field_name = component.get("name", f"field_{i}")
                result[field_name] = convert_bytes_to_hex(arg[i])
            return result
        
        raw_args = decode_abi(canonical_types, bytes.fromhex(tx["data"][10:]))
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
            elif isinstance(arg, tuple):
                # Handle tuple arguments with proper field names from ABI
                input_param = entry["inputs"][i]
                if input_param["type"] == "tuple" and "components" in input_param:
                    args.append(convert_tuple_to_dict(arg, input_param["components"]))
                else:
                    args.append(convert_bytes_to_hex(list(arg)))
            else:
                args.append(convert_bytes_to_hex(arg))
        
        return {**tx, "method": entry["name"], "args": args, "decoded_data": decode_nested_data(tx["data"], chainid)}
    except Exception as e:
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

