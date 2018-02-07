#!/usr/bin/python3.5
# -*- coding: utf-8 -*-

import hashlib
import binascii
import ecdsa

# Génération aléatoire
#random_seed = lambda n: "%032x"%ecdsa.util.randrange( pow(2,n) )  

class EC_key(object):
    
    def __init__( self, k ):
        secret = ecdsa.util.string_to_number(k)
        self.pubkey = ecdsa.ecdsa.Public_key( ecdsa.ecdsa.generator_secp256k1, ecdsa.ecdsa.generator_secp256k1 * secret )
        self.privkey = ecdsa.ecdsa.Private_key( self.pubkey, secret )
        self.secret = secret

# Clé publique : du point à la forme sérielle
def point_to_ser(P, comp=False):
    if comp:
        return bytes.fromhex( "{:02x}{:064x}".format( 2+(P.y()&1), P.x() ) )
    return bytes.fromhex( "04{:064x}{:064x}".format(P.x(), P.y()) )