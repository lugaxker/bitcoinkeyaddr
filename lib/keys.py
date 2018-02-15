#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ecdsa
from .base58 import *

WIF_PREFIX = 0x80

class EllipticCurveKey:
    
    def __init__( self, k ):
        secret = ecdsa.util.string_to_number(k)
        self.pubkey = ecdsa.ecdsa.Public_key( ecdsa.ecdsa.generator_secp256k1, ecdsa.ecdsa.generator_secp256k1 * secret )
        self.privkey = ecdsa.ecdsa.Private_key( self.pubkey, secret )
        self.secret = secret

def deserialize_wifkey( wifkey ):
    vch = Base58.decode_check( wifkey )
    assert len(vch) in (33,34)
    if vch[0] != WIF_PREFIX:
        raise BaseError('wrong version byte for WIF private key')
    compressed = (len(vch) == 34)
    
    return vch[1:33], compressed

# Clé publique : du point à la forme sérielle
def point_to_ser(P, compressed=False):
    if compressed:
        return bytes.fromhex( "{:02x}{:064x}".format( 2+(P.y()&1), P.x() ) )
    return bytes.fromhex( "04{:064x}{:064x}".format(P.x(), P.y()) )

