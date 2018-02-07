#!/usr/bin/python3.5
# -*- coding: utf-8 -*-

import imp
imp.load_module('bitcoinkeyaddr', *imp.find_module('lib'))

from bitcoinkeyaddr.address import *
from bitcoinkeyaddr.keys import EC_key, point_to_ser

# 1. Convertir adresse legacy (str) en adresse cash (str)
print()
print("1. Convertir adresse legacy (str) en adresse cash (str)")
print()

legacy_address = "15Fz48Z2R1gzcCwBxoKE7oqdJMiWavKFb9"
bytes_addr = Base58.decode_check(legacy_address)
hashaddr = bytes_addr[1:]
cash_address = Cashaddr.encode_full("bitcoincash", Cashaddr.PUBKEY_TYPE, hashaddr)

print("Adresse legacy ", legacy_address)
print("Adresse cash ", cash_address)

# 2. Calculer une adresse à partir d'une clé privée
print()
print("2. Calculer une adresse à partir d'une clé privée (WIF)")
print()

wifkey = "5JHpKWaBtKSe2vmRq1Jai622s18BLJcSCWXcXVKothR3eQY63wb"
k = Base58.decode_check(wifkey)
k = k[1:]
eckey = EC_key(k)
P = eckey.pubkey.point
K = point_to_ser(P)
payload = hash160(K)
assert len(payload) == 20
vpayload = bytes.fromhex( "00" + payload.hex() )
legacy_address = Base58.encode_check(vpayload)

print("Clé privée (WIF) ", wifkey)
Khex = K.hex()
print("Clé publique (hex)  {} {} {}".format(Khex[0:2], Khex[2:66], Khex[66:130]))
print("Adresse (legacy)", legacy_address)
print()