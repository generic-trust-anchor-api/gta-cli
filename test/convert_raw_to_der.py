import sys
import os
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

def convert_raw_to_der(input_file):
    with open(input_file, 'rb') as f:
        raw_signature = f.read()

    if len(raw_signature) != 64:
        raise ValueError("Invalid signature length. Expected 64 bytes.")

    r = int.from_bytes(raw_signature[:32], byteorder='big')
    s = int.from_bytes(raw_signature[32:], byteorder='big')
    der_signature = encode_dss_signature(r, s)

    # Schreibe Binärdaten direkt auf stdout
    os.write(sys.stdout.fileno(), der_signature)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 convert_signature.py <input_file>", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    convert_raw_to_der(input_file)