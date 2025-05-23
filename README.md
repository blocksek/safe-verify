# Safe Multisend Decoder

This repository contains a small Python script that decodes [Safe](https://safe.global) multisend transaction data. Contract ABIs are retrieved from the Etherscan API, so an API key is required when running the script locally.

## Requirements

- Python 3.9 or later
- Dependencies: `requests`, `eth-abi`, `web3`

The recommended way to install the dependencies is inside a Python virtual
environment so you do not pollute your global Python packages.

Create and activate a new virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Then install the dependencies with:

```bash
pip install requests eth-abi web3
```

When you are done using the decoder you can leave the virtual environment with:

```bash
deactivate
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

The script will output a JSON array describing each call contained in the multisend.

### Example

```bash
python multisend-decoder.py 0x0087...000003
```

This prints something like:

```json
[
  {
    "operation": 0,
    "to": "0x...",
    "value": 0,
    "data": "0x...",
    "method": "transfer",
    "args": ["0x...", 1000000000000000000]
  }
]
```

The script requires network access to `api.etherscan.io` in order to fetch verified contract ABIs.
