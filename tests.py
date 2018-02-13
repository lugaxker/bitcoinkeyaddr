#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bitcoinkeyaddr.address import *
from bitcoinkeyaddr.keys import EllipticCurveKey, point_to_ser

# 1. Convertir adresse legacy (str) en adresse cash (str)

print()
print("1. Convertir une adresse legacy (str) en une adresse cash (str)")
print()

address1 = Address.from_legacy_string( "15Fz48Z2R1gzcCwBxoKE7oqdJMiWavKFb9" )
print("Adresse legacy ", address1.to_legacy())
print("Adresse cash ", address1.to_full_cash())
print()

address2 = Address.from_legacy_string( "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC" )
print("Adresse legacy ", address2.to_legacy())
print("Adresse cash ", address2.to_full_cash())
print()

# 2. Convertir adresse cash (str) en adresse legacy (str)

print("2. Convertir une adresse cash (str) en une adresse legacy (str)")
print()

address3 = Address.from_cash_string( "qqhttulw2zdeklwgaujrruyxylad9nsdmsm4zcx8rj" )
print("Adresse cash ", address3.to_full_cash())
print("Adresse legacy ", address3.to_legacy())
print()

address4 = Address.from_cash_string( "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq" )
print("Adresse cash ", address4.to_full_cash())
print("Adresse legacy ", address4.to_legacy())
print()

# 3. Calculer une adresse à partir d'une clé privée

print("3. Calculer une adresse à partir d'une clé privée (WIF)")
print()

wifkey = "5JHpKWaBtKSe2vmRq1Jai622s18BLJcSCWXcXVKothR3eQY63wb"
address5 = prvkey_to_address( wifkey )

print("Clé privée (WIF) ", wifkey)
print("Adresse legacy", address5.to_legacy() )
print("Adresse cash", address5.to_full_cash() )
print()

# 4. Génération d'une nouvelle clé privée

print("4. Génération pseudo-aléatoire d'une nouvelle clé privée et de l'adresse associée")
print("ENTROPIE FAIBLE : NE PAS UTILISER")
print()

import ecdsa

_n = ecdsa.ecdsa.generator_secp256k1.order()
random_hexstr = "{:032x}".format( ecdsa.util.randrange( _n ) ).zfill(64)
k = bytes( [0x80] ) + bytes.fromhex( random_hexstr )
random_wifkey = Base58.encode_check(k)
random_address = prvkey_to_address( random_wifkey )

print("Clé privée (WIF) ", random_wifkey)
print("Adresse legacy", random_address.to_legacy() )
print("Adresse cash", random_address.to_full_cash() )
print()