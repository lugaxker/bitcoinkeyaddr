#!/usr/bin/python3.5
# -*- coding: utf-8 -*-

import imp
imp.load_module('bitcoinkeyaddr', *imp.find_module('lib'))

from bitcoinkeyaddr.address import *
from bitcoinkeyaddr.keys import EC_key, point_to_ser

# 1. Convertir adresse legacy (str) en adresse cash (str)

print()
print("1. Convertir une adresse legacy (str) en une adresse cash (str)")
print()

legacy_address = "15Fz48Z2R1gzcCwBxoKE7oqdJMiWavKFb9"
cash_address = legacy_to_cash( legacy_address )
print("Adresse legacy ", legacy_address)
print("Adresse cash ", cash_address)
print()

legacy_address = "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC"
cash_address = legacy_to_cash( legacy_address )
print("Adresse legacy ", legacy_address)
print("Adresse cash ", cash_address)
print()

# 2. Convertir adresse cash (str) en adresse legacy (str)

print("2. Convertir une adresse cash (str) en une adresse legacy (str)")
print()

cash_address = "bitcoincash:qqhttulw2zdeklwgaujrruyxylad9nsdmsm4zcx8rj"
legacy_address = cash_to_legacy( cash_address )
print("Adresse cash ", cash_address)
print("Adresse legacy ", legacy_address)
print()

cash_address = "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq"
legacy_address = cash_to_legacy( cash_address )
print("Adresse cash ", cash_address)
print("Adresse legacy ", legacy_address)
print()

# 3. Calculer une adresse à partir d'une clé privée

print("3. Calculer une adresse à partir d'une clé privée (WIF)")
print()

wifkey = "5JHpKWaBtKSe2vmRq1Jai622s18BLJcSCWXcXVKothR3eQY63wb"
legacy_address = prvkey_to_address( wifkey, 1)
cash_address = prvkey_to_address( wifkey, 0)

print("Clé privée (WIF) ", wifkey)
print("Adresse legacy ", legacy_address)
print("Adresse cash ", cash_address)
print()

# 4. Génération d'une nouvelle clé privée

print("4. Génération pseudo-aléatoire d'une nouvelle clé privée et de l'adresse associée")
print("ENTROPIE FAIBLE : NE PAS UTILISER")
print()

import ecdsa

_n = ecdsa.ecdsa.generator_secp256k1.order()
random_hexstr = "{:032x}".format( ecdsa.util.randrange( _n ) )
k = bytes.fromhex( "80" + random_hexstr ) 
random_wifkey = Base58.encode_check(k)
random_key = EC_key( k[1:] )
P = random_key.pubkey.point
K = point_to_ser(P)
payload = hash160(K)
assert len(payload) == 20
vpayload = bytes.fromhex( "00" + payload.hex() )
random_address = Base58.encode_check(vpayload)

print("Clé privée (WIF) ", random_wifkey)
print("Adresse legacy", random_address)
print("Adresse cash", legacy_to_cash( random_address ) )
print()