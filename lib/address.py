#!/usr/bin/python3.5
# -*- coding: utf-8 -*-

# From Electron Cash - lightweight Bitcoin client
# Copyright (C) 2017 The Electron Cash Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import hashlib

from .keys import *

_sha256 = hashlib.sha256
_new_hash = hashlib.new
hex_to_bytes = bytes.fromhex

class AddressError(Exception):
    '''Exception used for Address errors.'''

# Utility functions

def to_bytes(x):
    '''Convert to bytes which is hashable.'''
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    raise TypeError('{} is not bytes ({})'.format(x, type(x)))

#def hash_to_hex_str(x):
    #'''Convert a big-endian binary hash to displayed hex string.

    #Display form of a binary hash is reversed and converted to hex.
    #'''
    #return bytes(reversed(x)).hex()

#def hex_str_to_hash(x):
    #'''Convert a displayed hex string to a binary hash.'''
    #return bytes(reversed(hex_to_bytes(x)))

def bytes_to_int(be_bytes):
    '''Interprets a big-endian sequence of bytes as an integer'''
    return int.from_bytes(be_bytes, 'big')

def int_to_bytes(value):
    '''Converts an integer to a big-endian sequence of bytes'''
    return value.to_bytes((value.bit_length() + 7) // 8, 'big')

def sha256(x):
    '''Simple wrapper of hashlib sha256.'''
    return _sha256(x).digest()

def double_sha256(x):
    '''SHA-256 of SHA-256, as used extensively in bitcoin.'''
    return sha256(sha256(x))

def ripemd160(x):
    '''Simple wrapper of hashlib ripemd160.'''
    h = _new_hash('ripemd160')
    h.update(x)
    return h.digest()

def hash160(x):
    '''RIPEMD-160 of SHA-256.

    Used to make bitcoin addresses from pubkeys.'''
    return ripemd160(sha256(x))


###

class Base58Error(Exception):
    '''Exception used for Base58 errors.'''

class Base58(object):
    '''Class providing base 58 functionality.'''

    chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    assert len(chars) == 58
    cmap = {c: n for n, c in enumerate(chars)}

    @staticmethod
    def char_value(c):
        val = Base58.cmap.get(c)
        if val is None:
            raise Base58Error('invalid base 58 character "{}"'.format(c))
        return val

    @staticmethod
    def decode(txt):
        """Decodes txt into a big-endian bytearray."""
        if not isinstance(txt, str):
            raise TypeError('a string is required')

        if not txt:
            raise Base58Error('string cannot be empty')

        value = 0
        for c in txt:
            value = value * 58 + Base58.char_value(c)

        result = int_to_bytes(value)

        # Prepend leading zero bytes if necessary
        count = 0
        for c in txt:
            if c != '1':
                break
            count += 1
        if count:
            result = bytes(count) + result

        return result

    @staticmethod
    def encode(be_bytes):
        """Converts a big-endian bytearray into a base58 string."""
        value = bytes_to_int(be_bytes)

        txt = ''
        while value:
            value, mod = divmod(value, 58)
            txt += Base58.chars[mod]

        for byte in be_bytes:
            if byte != 0:
                break
            txt += '1'

        return txt[::-1]

    @staticmethod
    def decode_check(txt):
        '''Decodes a Base58Check-encoded string to a payload.  The version
        prefixes it.'''
        be_bytes = Base58.decode(txt)
        result, check = be_bytes[:-4], be_bytes[-4:]
        if check != double_sha256(result)[:4]:
            raise Base58Error('invalid base 58 checksum for {}'.format(txt))
        return result

    @staticmethod
    def encode_check(payload):
        """Encodes a payload bytearray (which includes the version byte(s))
        into a Base58Check string."""
        be_bytes = payload + double_sha256(payload)[:4]
        return Base58.encode(be_bytes)
    
###

class CashAddr(object):
    
    _CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    @staticmethod
    def _polymod(values):
        """Internal function that computes the cashaddr checksum."""
        c = 1
        for d in values:
            c0 = c >> 35
            c = ((c & 0x07ffffffff) << 5) ^ d
            if (c0 & 0x01):
                c ^= 0x98f2bc8e61
            if (c0 & 0x02):
                c ^= 0x79b76d99e2
            if (c0 & 0x04):
                c ^= 0xf33e5fb3c4
            if (c0 & 0x08):
                c ^= 0xae2eabe2a8
            if (c0 & 0x10):
                c ^= 0x1e4f43e470
        retval= c ^ 1
        return retval
    
    @staticmethod
    def _prefix_expand(prefix):
        """Expand the prefix into values for checksum computation."""
        retval = bytearray(ord(x) & 0x1f for x in prefix)
        # Append null separator
        retval.append(0)
        return retval
    
    @staticmethod
    def _create_checksum(prefix, data):
        """Compute the checksum values given prefix and data."""
        values = CashAddr._prefix_expand(prefix) + data + bytes(8)
        polymod = CashAddr._polymod(values)
        # Return the polymod expanded into eight 5-bit elements
        return bytes((polymod >> 5 * (7 - i)) & 31 for i in range(8))

    @staticmethod
    def _convertbits(data, frombits, tobits, pad=True):
        """General power-of-2 base conversion."""
        acc = 0
        bits = 0
        ret = bytearray()
        maxv = (1 << tobits) - 1
        max_acc = (1 << (frombits + tobits - 1)) - 1
        for value in data:
            acc = ((acc << frombits) | value ) & max_acc
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)

        if pad and bits:
            ret.append((acc << (tobits - bits)) & maxv)

        return ret

    @staticmethod
    def _pack_addr_data(kind, addr_hash):
        """Pack addr data with version byte"""
        version_byte = kind << 3

        offset = 1
        encoded_size = 0
        if len(addr_hash) >= 40:
            offset = 2
            encoded_size |= 0x04
        encoded_size |= (len(addr_hash) - 20 * offset) // (4 * offset)

        # invalid size?
        if ((len(addr_hash) - 20 * offset) % (4 * offset) != 0
                or not 0 <= encoded_size <= 7):
            raise ValueError('invalid address hash size {}'.format(addr_hash))

        version_byte |= encoded_size

        data = bytes([version_byte]) + addr_hash
        return CashAddr._convertbits(data, 8, 5, True)

    @staticmethod
    def _decode_payload(addr):
        """Validate a cashaddr string.

        Throws CashAddr.Error if it is invalid, otherwise returns the
        triple

        (prefix,  payload)

        without the checksum.
        """
        lower = addr.lower()
        if lower != addr and addr.upper() != addr:
            raise ValueError('mixed case in address: {}'.format(addr))

        parts = lower.split(':', 1)
        if len(parts) != 2:
            raise ValueError("address missing ':' separator: {}".format(addr))

        prefix, payload = parts
        if not prefix:
            raise ValueError('address prefix is missing: {}'.format(addr))
        if not all(33 <= ord(x) <= 126 for x in prefix):
            raise ValueError('invalid address prefix: {}'.format(prefix))
        if not (8 <= len(payload) <= 124):
            raise ValueError('address payload has invalid length: {}'
                            .format(len(addr)))
        try:
            data = bytes(CashAddr._CHARSET.find(x) for x in payload)
        except ValueError:
            raise ValueError('invalid characters in address: {}'
                                .format(payload))

        if CashAddr._polymod(CashAddr._prefix_expand(prefix) + data):
            raise ValueError('invalid checksum in address: {}'.format(addr))

        if lower != addr:
            prefix = prefix.upper()

        # Drop the 40 bit checksum
        return prefix, data[:-8]

    #
    # External Interface
    #

    PUBKEY_TYPE = 0
    SCRIPT_TYPE = 1

    @staticmethod
    def decode(address):
        '''Given a cashaddr address, return a triple

            (prefix, kind, hash)
        '''
        if not isinstance(address, str):
            raise TypeError('address must be a string')

        prefix, payload = CashAddr._decode_payload(address)

        # Ensure there isn't extra padding
        extrabits = len(payload) * 5 % 8
        if extrabits >= 5:
            raise ValueError('excess padding in address {}'.format(address))

        # Ensure extrabits are zeros
        if payload[-1] & ((1 << extrabits) - 1):
            raise ValueError('non-zero padding in address {}'.format(address))

        decoded = CashAddr._convertbits(payload, 5, 8, False)
        version = decoded[0]
        addr_hash = bytes(decoded[1:])
        size = (version & 0x03) * 4 + 20
        # Double the size, if the 3rd bit is on.
        if version & 0x04:
            size <<= 1
        if size != len(addr_hash):
            raise ValueError('address hash has length {} but expected {}'
                            .format(len(addr_hash), size))

        kind = version >> 3
        if kind not in (CashAddr.SCRIPT_TYPE, CashAddr.PUBKEY_TYPE):
            raise ValueError('unrecognised address type {}'.format(kind))

        return prefix, kind, addr_hash

    @staticmethod
    def encode(prefix, kind, addr_hash):
        """Encode a cashaddr address without prefix and separator."""
        if not isinstance(prefix, str):
            raise TypeError('prefix must be a string')

        if not isinstance(addr_hash, (bytes, bytearray)):
            raise TypeError('addr_hash must be binary bytes')

        if kind not in (CashAddr.SCRIPT_TYPE, CashAddr.PUBKEY_TYPE):
            raise ValueError('unrecognised address type {}'.format(kind))

        payload = CashAddr._pack_addr_data(kind, addr_hash)
        checksum = CashAddr._create_checksum(prefix, payload)
        return ''.join([CashAddr._CHARSET[d] for d in (payload + checksum)])

    @staticmethod
    def encode_full(prefix, kind, addr_hash):
        """Encode a full cashaddr address, with prefix and separator."""
        return ':'.join([prefix, CashAddr.encode(prefix, kind, addr_hash)])

class Address:
    ''' Address. '''
    
    # Address kinds
    ADDR_P2PKH = 0
    ADDR_P2SH = 1

    # Address formats
    FMT_CASH = 0
    FMT_LEGACY = 1
    
    CASHADDR_PREFIX = "bitcoincash"
    
    def __init__(self, hash160, kind):
        ''' Initialisateur '''
        assert kind in (self.ADDR_P2PKH, self.ADDR_P2SH)
        self.kind = kind
        hash160 = to_bytes(hash160)
        assert len(hash160) == 20
        self.hash160 = hash160
        
        
    @classmethod
    def from_cash_string(self, string):
        '''Initialize from a cash address string.'''
        prefix = self.CASHADDR_PREFIX
        #if string.upper() == string:
            #prefix = prefix.upper()
        if not string.startswith(prefix + ':'):
            string = ':'.join([prefix, string])
        addr_prefix, kind, addr_hash = CashAddr.decode(string)
        if addr_prefix != prefix:
            raise AddressError('address has unexpected prefix {}'
                               .format(addr_prefix))
        return self(addr_hash, kind)
    
    @classmethod
    def from_legacy_string(self, string):
        '''Initialize from a legacy address string.'''
        vpayload = Base58.decode_check( string )
        verbyte, addr_hash = vpayload[0], vpayload[1:]
        if verbyte == 0:
            kind = self.ADDR_P2PKH
        elif verbyte == 5:
            kind = self.ADDR_P2SH
        else:
            raise AddressError("unknown version byte: {}".format(verbyte))
        return self(addr_hash, kind)
    
    @classmethod
    def from_string(self, string):
        '''Construct from an address string.'''
        if len(string) > 35:
            return self.from_cash_string(string)
        else:
            return self.from_legacy_string(string)
        
    @classmethod
    def from_pubkey(self, pubkey):
        '''Returns a P2PKH address from a public key.  The public key can
        be bytes or a hex string.'''
        if isinstance(pubkey, str):
            pubkey = bytes.fromhex(pubkey)
        #PublicKey.validate(pubkey)
        return self(hash160(pubkey), self.ADDR_P2PKH)
    
    @classmethod
    def from_P2PKH_hash(self, hash160):
        '''Initialize from a P2PKH hash160.'''
        return self(hash160, self.ADDR_P2PKH)
            
    def to_cash(self):
        return CashAddr.encode(self.CASHADDR_PREFIX, self.kind, self.hash160)
    
    def to_full_cash(self):
        return CashAddr.encode_full(self.CASHADDR_PREFIX, self.kind, self.hash160)
    
    def to_legacy(self):
        if self.kind == self.ADDR_P2PKH:
            verbyte = 0
        else:
            verbyte = 5
        return Base58.encode_check(bytes([verbyte]) + self.hash160)
    
    def to_string(self, fmt):
        if fmt == self.FMT_CASH:
            return self.to_cash()
        elif fmt == self.FMT_LEGACY:
            return self.to_legacy()
        else:
            raise AddressError('unrecognised format')
        
    def to_full_string(self, fmt):
        if fmt == self.FMT_CASH:
            return self.to_full_cash()
        elif fmt == self.FMT_LEGACY:
            return self.to_legacy()
        else:
            raise AddressError('unrecognised format')
        
    def __str__(self):
        return self.to_full_string(self.FMT_CASH)

    def __repr__(self):
        return '<Address {}>'.format(self.__str__())
    
def prvkey_to_address( wifkey ):
    ''' Generate simple address from simple private key (WIF). 
    Formats : CASHADDR = 0, LEGACY = 1.'''
    k = Base58.decode_check( wifkey )
    verbyte, prvkey_hash = k[0], k[1:]
    eckey = EllipticCurveKey( prvkey_hash )
    K = point_to_ser( eckey.pubkey.point )
    address = Address.from_pubkey(K)
    
    return address