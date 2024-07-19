# Bitcoin Address Generator

This Python script generates various types of Bitcoin addresses for both mainnet and signet networks. It supports BIP32 hierarchical deterministic wallets and allows users to input custom derivation paths.

## Features

- Supports both Bitcoin mainnet and signet networks
- Generates P2PKH, P2SH, and Bech32 (P2WPKH) addresses
- Allows custom BIP32 derivation paths
- Provides private key in both hexadecimal and WIF formats
- Displays public key in hexadecimal format

## Requirements

- Python 3.6+
- `ecdsa` library
- `base58` library
- `bech32` library

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/SzczepanBEN/bitcoin-address-generator.git
   
   cd bitcoin-address-generator
   ```

3. Install the required dependencies:
   ```
   pip install ecdsa base58 bech32
   ```

## Usage

Run the script using Python:

```
python bitcoin_address_generator.py
```

Follow the prompts to:

1. Choose the network (mainnet or signet)
2. Select a derivation path (default or custom)
3. Enter a random string as a seed

The script will then generate and display the following information:

- Derivation Path
- Private Key (hexadecimal)
- Private Key (WIF - Wallet Import Format)
- Public Key (hexadecimal)
- P2PKH Address
- P2SH Address
- Bech32 Address (P2WPKH)

## Security Considerations

- This script is for educational purposes only. Do not use it to generate addresses for storing real funds unless you fully understand the implications and risks.
- The security of your Bitcoin addresses depends on the randomness and secrecy of your seed. Ensure you're using a secure method to generate and store your seed.
- Never share your private keys or seed with anyone.

## Contributing

Contributions to improve the script or add new features are welcome. Please feel free to submit a pull request or open an issue to discuss potential changes.

## License

This project is open source and available under the [MIT License](LICENSE).

## Disclaimer

This software is provided "as is", without warranty of any kind. Use at your own risk. The authors or copyright holders shall not be liable for any claim, damages, or other liability arising from the use of the software.