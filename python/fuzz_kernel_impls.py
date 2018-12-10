#!/usr/bin/env python3
#
# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import argparse
import errno
import random
import socket
import sys

import adiantum

def fail(msg):
    sys.stderr.write(f'Error: {msg}\n')
    sys.exit(1)

class AdiantumKernelImpl():

    def __init__(self, kern_algname):
        self.alg_fd = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        self.alg_fd.bind(('skcipher', kern_algname))

    def _crypt(self, message, key, tweak, op):
        self.alg_fd.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, key)
        req, _ = self.alg_fd.accept()
        req.sendmsg_afalg([message], op=op, iv=tweak)
        (data, _, _, _) = req.recvmsg(len(message) + 256)
        if len(data) != len(message):
            fail("{} didn't preserve length!".format(
                "Encryption" if op == socket.ALG_OP_ENCRYPT else "Decryption"))
        return data

    def encrypt(self, plaintext, key, tweak):
        return self._crypt(plaintext, key, tweak, socket.ALG_OP_ENCRYPT)

    def decrypt(self, ciphertext, key, tweak):
        return self._crypt(ciphertext, key, tweak, socket.ALG_OP_DECRYPT)

def do_test_impl(args, kern_impl, ref_impl):

    sizes = []

    for _ in range(args.num_msgs):
        size = max(16, int(random.expovariate(1 / args.avg_msgsize)))
        orig_msg = bytes(random.getrandbits(8) for _ in range(size))
        key = bytes(random.getrandbits(8) for _ in range(32))
        tweak = bytes(random.getrandbits(8) for _ in range(32))

        sizes.append(size)

        ref_ctext = ref_impl.encrypt(orig_msg, key, tweak)
        kern_ctext = kern_impl.encrypt(orig_msg, key, tweak)
        if ref_ctext != kern_ctext:
            fail('Encryption results differed')

        ref_ptext = ref_impl.decrypt(ref_ctext, key, tweak)
        kern_ptext = kern_impl.decrypt(ref_ctext, key, tweak)
        if ref_ptext != kern_ptext:
            fail('Decryption results differed')
        if ref_ptext != orig_msg:
            fail("Decryption didn't invert encryption")

    #print(f'Tested sizes: {sizes}')


def test_impl(args, kern_algname, variant_selector, required=True):
    try:
        kern_impl = AdiantumKernelImpl(kern_algname)
    except OSError as ex:
        is_algnotfound = (ex.errno == errno.EAFNOSUPPORT or
                          ex.errno == errno.ENOENT)
        if is_algnotfound and not required:
            return
        sys.stderr.write('Unable to set up AF_ALG socket for Adiantum!\n')
        if is_algnotfound:
            sys.stderr.write('Try enabling CONFIG_CRYPTO_USER_API_SKCIPHER and CONFIG_CRYPTO_ADIANTUM.\n')
            sys.exit(1)
        raise ex

    print(f'Testing {kern_algname}...')

    ref_impl = adiantum.Adiantum()
    ref_impl.choose_variant(variant_selector)

    do_test_impl(args, kern_impl, ref_impl)

def is_Adiantum_XChaCha_AES(variant, chacha_nrounds):
    return variant == {
        'cipher': 'Adiantum',
        'streamcipher': {
            'cipher': 'XChaCha',
            'rounds': chacha_nrounds,
            'delgatevariant': {
                'cipher': 'ChaCha',
                'rounds': chacha_nrounds,
                'lengths': {
                    'key': 32,
                    'nonce': 8
                }
            },
            'lengths': {
                'key': 32,
                'nonce': 24
            }
        },
        'blockcipher': {
            'cipher': 'AES',
            'lengths': {
                'block': 16,
                'key': 32
            }
        },
        'lengths': {
            'key': 32
        }
    }

XCHACHA_IMPLS = ['generic', 'neon', 'simd']
AES_IMPLS = ['generic', 'arm', 'ce', 'aesni']
NHPOLY1305_IMPLS = ['generic', 'neon', 'sse2', 'avx2']

def main():
    parser = argparse.ArgumentParser(description="""Use AF_ALG to verify that
    the kernel implementation of Adiantum produces the same results as the
    reference implementation.""")
    parser.add_argument('--num-msgs', type=int, default=128,
                        help='number of messages to test per implementation')
    parser.add_argument('--avg-msgsize', type=int, default=1024,
                        help='typical message size in bytes')
    parser.add_argument('--all-impls', action='store_true',
                        help='test all available implementations, not just the default one')
    args = parser.parse_args()

    print('Arguments:')
    print(f'\tNumber of messages:                 {args.num_msgs}')
    print(f'\tTypical message size:               {args.avg_msgsize}')
    print(f'\tTest non-default implementations:   {args.all_impls}')
    print('')

    for chacha_nrounds in [12, 20]:
        variant_selector = lambda variant: \
                is_Adiantum_XChaCha_AES(variant, chacha_nrounds)
        test_impl(args, f'adiantum(xchacha{chacha_nrounds},aes)',
                  variant_selector)
        if args.all_impls:
            for xchacha_impl in XCHACHA_IMPLS:
                for aes_impl in AES_IMPLS:
                    for nhpoly1305_impl in NHPOLY1305_IMPLS:
                        test_impl(args,
                                  f'adiantum(xchacha{chacha_nrounds}-{xchacha_impl},aes-{aes_impl},nhpoly1305-{nhpoly1305_impl})',
                                  variant_selector, required=False)

if __name__ == "__main__":
    main()
