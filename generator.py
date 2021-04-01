import secrets
import hashlib


class KeyGenerator:
    def generate_key(self):
        key = hex(secrets.randbits(256))[2:]
        # HEX to WIF
        prefix = 'ef'
        ext_key = prefix + key
        checksum = hashlib.sha256(hashlib.sha256(bytes.fromhex(ext_key)).digest()).digest()[0:4]
        checksum = checksum.hex()
        ext_key_with_checksum = ext_key + checksum
        wif_key = self.base58(ext_key_with_checksum)

        return key, wif_key

    @staticmethod
    def base58(address_hex):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        # Get the number of leading zeros and convert hex to decimal
        leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
        # Convert hex to decimal
        address_int = int(address_hex, 16)
        # Append digits to the start of string
        while address_int > 0:
            digit = address_int % 58
            digit_char = alphabet[digit]
            b58_string = digit_char + b58_string
            address_int //= 58
        # Add '1' for each 2 leading zeros
        ones = leading_zeros // 2
        for one in range(ones):
            b58_string = '1' + b58_string
        return b58_string