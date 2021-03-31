from gen import KeyGenerator
from bitcoin import BitcoinWallet


def main():
    kgen = KeyGenerator()
    private_key, private_key_wif = kgen.generate_key()
    address, public_key = BitcoinWallet.generate_address(private_key)

    print('Address:', address)
    print('Public: ', public_key)
    print('Private:', private_key)
    print('Private WIF:', private_key_wif)


main()