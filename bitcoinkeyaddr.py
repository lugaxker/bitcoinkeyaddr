#!/usr/bin/python3.5
# -*- coding: utf-8 -*-

import imp
imp.load_module('bitcoinkeyaddr', *imp.find_module('lib'))

from bitcoinkeyaddr.address import *

# 1. Convertir adresse legacy (str) en adresse cash (str)

legacy_address = "15Fz48Z2R1gzcCwBxoKE7oqdJMiWavKFb9"
print("Adresse legacy", legacy_address)
bytes_addr = Base58.decode_check(legacy_address)
hashaddr = bytes_addr[1:]

cash_address = Cashaddr.encode_full("bitcoincash", Cashaddr.PUBKEY_TYPE, hashaddr)
print("Adresse cash", cash_address)

# 2. Calculer une adresse à partir d'une clé privée

prvkey = "5JHpKWaBtKSe2vmRq1Jai622s18BLJcSCWXcXVKothR3eQY63wb"