import hashlib
import hmac
import ecdsa
import base58
import bech32
from ecdsa.curves import SECP256k1
from ecdsa.util import string_to_number, number_to_string

# Network parameters
NETWORKS = {
    'mainnet': {
        'pubkey_address': 0x00,
        'script_address': 0x05,
        'wif_prefix': 0x80,
        'bech32_hrp': 'bc'
    },
    'signet': {
        'pubkey_address': 0x6f,
        'script_address': 0xc4,
        'wif_prefix': 0xef,
        'bech32_hrp': 'tb'
    }
}

def generate_master_key(seed):
    return hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()[:32]

def derive_master_chain_code(seed):
    return hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()[32:]

def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()

def ckd_priv(parent_key, parent_chain_code, i):
    if i >= 2**31:
        data = b'\x00' + parent_key + i.to_bytes(4, 'big')
    else:
        data = private_key_to_public_key(parent_key) + i.to_bytes(4, 'big')

    I = hmac_sha512(parent_chain_code, data)
    I_L, I_R = I[:32], I[32:]

    k_i = (string_to_number(parent_key) + string_to_number(I_L)) % SECP256k1.order
    k_i = number_to_string(k_i, SECP256k1.order)

    return k_i, I_R

def derive_child_key(parent_key, parent_chain_code, path):
    for child_index in path:
        parent_key, parent_chain_code = ckd_priv(parent_key, parent_chain_code, child_index)
    return parent_key

def parse_path(path):
    if path.lower().startswith('m/'):
        path = path[2:]
    try:
        return [int(x) if "'" not in x else 2**31 + int(x[:-1]) for x in path.split('/')]
    except ValueError:
        raise ValueError("Invalid derivation path. Please use the format: m/44'/0'/0'/0/0")

def private_key_to_wif(private_key, network):
    version_prefix = bytes([NETWORKS[network]['wif_prefix']])
    extended_key = version_prefix + private_key
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + checksum)
    return wif.decode('utf-8')

def private_key_to_public_key(private_key):
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    return b'\x04' + verifying_key.to_string()

def public_key_to_bech32_address(public_key, network):
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    version = 0
    bech32_encoded = bech32.encode(NETWORKS[network]['bech32_hrp'], version, ripemd160_hash)
    return bech32_encoded

def public_key_to_p2pkh_address(public_key, network):
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    version_prefix = bytes([NETWORKS[network]['pubkey_address']])
    extended_hash = version_prefix + ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
    address = base58.b58encode(extended_hash + checksum)
    return address.decode('utf-8')

def public_key_to_p2sh_address(public_key, network):
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    version_prefix = bytes([NETWORKS[network]['script_address']])
    extended_hash = version_prefix + ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
    address = base58.b58encode(extended_hash + checksum)
    return address.decode('utf-8')

def get_valid_path():
    default_path = "m/44'/0'/0'/0/0"
    while True:
        use_default = input(f"Use default derivation path ({default_path})? (y/n): ").lower() == 'y'

        if use_default:
            return default_path

        path = input("Enter custom derivation path (e.g., m/44'/0'/0'/0/1): ")
        try:
            parse_path(path)
            return path
        except ValueError as e:
            print(f"Error: {e}")
            retry = input("Would you like to try again? (y/n): ").lower()
            if retry != 'y':
                print("Using default path.")
                return default_path

def get_network():
    while True:
        network = input("Choose network (mainnet/signet): ").lower()
        if network in NETWORKS:
            return network
        print("Invalid network. Please choose 'mainnet' or 'signet'.")

def main():
    network = get_network()
    path = get_valid_path()

    seed_input = input("Enter any random string as a seed: ")
    seed = hashlib.sha256(seed_input.encode()).digest()

    master_key = generate_master_key(seed)
    master_chain_code = derive_master_chain_code(seed)

    parsed_path = parse_path(path)
    private_key = derive_child_key(master_key, master_chain_code, parsed_path)

    public_key = private_key_to_public_key(private_key)
    bech32_address = public_key_to_bech32_address(public_key, network)
    p2pkh_address = public_key_to_p2pkh_address(public_key, network)
    p2sh_address = public_key_to_p2sh_address(public_key, network)
    wif = private_key_to_wif(private_key, network)

    print(f"\nBitcoin Address Information ({network.capitalize()}):")
    print(f"Derivation Path: {path}")
    print(f"Private Key (hex): {private_key.hex()}")
    print(f"WIF: {wif}")
    print(f"Public Key (hex): {public_key.hex()}")
    print(f"P2PKH Address: {p2pkh_address}")
    print(f"P2SH Address: {p2sh_address}")
    print(f"Bech32 Address (P2WPKH): {bech32_address}")

if __name__ == "__main__":
    main()