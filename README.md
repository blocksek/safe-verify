# Safe Multisend Decoder

A Python tool to decode Safe multisend transaction blobs into human-readable format with enhanced proxy contract support and nested data decoding.

## Features

- **Multisend Decoding**: Decodes Safe multisend transaction data into individual operations
- **Proxy Contract Support**: Automatically detects and resolves proxy contracts to their implementation ABIs
- **ABI-Aware Decoding**: Fetches contract ABIs from Etherscan for precise method identification
- **Fallback Signatures**: Built-in common Safe function signatures for when ABI lookup fails
- **Nested Data Decoding**: Recursively decodes nested transaction data within function arguments
- **Multi-Chain Support**: Supports multiple chains via chainid parameter
- **Detailed Output**: Provides comprehensive transaction breakdown with method names, arguments, and operation types

## Enhanced Capabilities

### Proxy Contract Resolution
The decoder automatically detects proxy contracts (contracts with only constructor/fallback functions) and attempts to resolve their implementation contracts using standard proxy patterns:
- EIP-1967 proxies
- OpenZeppelin proxies

### Common Function Signatures
Built-in support for common Safe functions even when ABI lookup fails:
- `swapOwner(address,address,address)` - Replace a Safe owner
- `addOwnerWithThreshold(address,uint256)` - Add new owner with threshold
- `multicall(bytes[])` - Batch multiple calls
- `execTransaction(...)` - Execute a Safe transaction

### Operation Types
Decodes Safe operation types:
- `0` = CALL (standard function call)
- `1` = DELEGATECALL (executes code in current context)  
- `2` = CREATE (contract creation)

## Requirements

- Python 3.9 or later
- Dependencies: `requests`, `eth-abi`, `web3`
- Etherscan API key

## Installation

```bash
pip install requests eth-abi web3
```

## Usage

1. Obtain an Etherscan API key from <https://etherscan.io/>.
2. Export it in your environment:

```bash
export ETHERSCAN_API_KEY=<your key>
```

3. Run the decoder and provide the hex encoded multisend transaction blob:

```bash
python multisend-decoder.py <hex_blob> [--chainid CHAIN_ID]
```

`--chainid` defaults to `1` (Ethereum mainnet). Use the appropriate chain ID for the transaction you are decoding.

### Example

```bash
python multisend-decoder.py 0x0087787389bb2eb2ec8fe4aa6a2e33d671d925a60f...
```

### Enhanced Output

The tool outputs comprehensive JSON with decoded transaction details:

```json
[
  {
    "operation": 0,
    "to": "0x87787389BB2Eb2EC8Fe4aA6a2e33D671d925A60f",
    "value": 0,
    "data": "0xe318b52b0000000000000000000000001f994abb0c61f8eb390616e71406b059537856630000000000000000000000001d4f0eb70a2de1327c9e48cbd794d9c3c40192a70000000000000000000000001887e7a7cefe6a778f12f4e5b72beaaca41a86ee",
    "method": "swapOwner",
    "args": [
      "0x1f994abb0c61f8eb390616e71406b05953785663",
      "0x1d4f0eb70a2de1327c9e48cbd794d9c3c40192a7", 
      "0x1887e7a7cefe6a778f12f4e5b72beaaca41a86ee"
    ],
    "decoded_data": {
      "method": "swapOwner",
      "args": [
        "0x1f994abb0c61f8eb390616e71406b05953785663",
        "0x1d4f0eb70a2de1327c9e48cbd794d9c3c40192a7",
        "0x1887e7a7cefe6a778f12f4e5b72beaaca41a86ee"
      ],
      "signature": "0xe318b52b"
    }
  }
]
```

### Output Fields

- `operation`: Operation type (0=CALL, 1=DELEGATECALL, 2=CREATE)
- `to`: Target contract address
- `value`: ETH value sent with transaction
- `data`: Raw transaction data
- `method`: Decoded method name
- `args`: Decoded function arguments
- `decoded_data`: Detailed breakdown of the transaction data
- `error`: Error message (only present when decoding fails)

## Options

- `--chainid`: Chain ID for ABI lookups (default: 1 for Ethereum mainnet)

## Environment Variables

- `ETHERSCAN_API_KEY`: Required for contract ABI fetching

## Error Handling

The decoder gracefully handles various scenarios:
- Unverified contracts on Etherscan
- Proxy contracts without accessible implementation
- Unknown function signatures (falls back to common signatures)
- Network timeouts or API errors

When ABI lookup fails, the decoder attempts to use built-in common function signatures before marking methods as "UNKNOWN".

The script requires network access to `api.etherscan.io` in order to fetch verified contract ABIs.
