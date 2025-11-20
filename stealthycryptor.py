from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad

# === Load raw shellcode ===
with open("payload.bin", "rb") as f:
    plaintext = f.read()

# === Generate random AES-256 key and IV ===
key = get_random_bytes(32)
iv = get_random_bytes(16)

# === Encrypt the payload ===
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

# === Save encrypted payload ===
with open("payload.enc", "wb") as f:
    f.write(ciphertext)

# === Output C++-style key/iv ===
def to_cpp_array(name, byte_data):
    hex_str = ', '.join(f'0x{b:02x}' for b in byte_data)
    return f"BYTE {name}[{len(byte_data)}] = {{ {hex_str} }};"

print("[+] AES Key and IV for your loader:")
print(to_cpp_array("aesKey", key))
print(to_cpp_array("aesIV", iv))
