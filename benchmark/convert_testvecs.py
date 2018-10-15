#!/usr/bin/env python3
# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

"""Convert JSON test vectors from ../test_vectors/ into C headers in ./testvectors/"""

import argparse
import pathlib
import random
import sys

scriptdir = pathlib.Path(__file__).parent
targetdir = scriptdir / "testvectors"
topdir = scriptdir.resolve().parent

sys.path.append(str(topdir / "python"))

import hexjson

def write_in_groups(f, prefix, separator, suffix, emptyval, convert, values):
    first = True
    for v in values:
        if first:
            f.write(prefix)
            first = False
        else:
            f.write(separator)
        convert(f, v)
    if first:
        f.write(emptyval)
    else:
        f.write(suffix)

def group_string(s, l):
    for i in range(0, len(s), l):
        yield s[i:i+l]

def write_as_c_string(f, b):
    hex = ''.join(f"\\x{a:02x}" for a in b)
    f.write(f'"{hex}"')

def write_data_field(f, prefix, separator, suffix, emptyval, value):
    write_in_groups(f, prefix, separator, suffix, emptyval,
        write_as_c_string, group_string(value, 8))

def write_testvec_structs(f, struct, name, entries):
    f.write(f"static const struct {struct} {name}[] = {{\n")
    for vec in entries:
        f.write("\t{\n")
        for k, v in vec.items():
            f.write(f"\t\t.{k}\t= {{.len = {len(v)}, .data =")
            write_data_field(f, '\n\t\t\t', '\n\t\t\t', '\n\t\t', ' ""', v)
            f.write('},\n')
        f.write("\t},\n")
    f.write(f"}};\n\n")

def write_linux_testvec_hexfield(f, field_name, value):
    """Write a hex field to a Linux crypto test vector."""
    f.write(f'\t\t.{field_name}\t=')
    write_data_field(f, ' ', '\n\t\t\t  ', '', ' ""', value)
    f.write(',\n')

def write_linux_testvec_field(f, field_name, value):
    """Write a general field to a Linux crypto test vector."""
    f.write(f"\t\t.{field_name}\t= {value},\n")

def write_linux_testvecs(f, struct, cipher_name, convert, entries):
    f.write(f"static const struct {struct} {cipher_name}_tv_template[] = {{\n")
    write_in_groups(f, "\t{\n", "\t}, {\n", "\t}", "", convert, entries)
    f.write('\n};\n\n')

def partition_int(length, parts):
    """Randomly generate parts integers >0 that sum to length"""
    splits = random.sample(range(1, length), parts -1)
    splits.sort()
    return [b - a for a, b in zip([0] + splits, splits + [length])]

def write_scatterlist_splits(f, length, allow_also_not_np):
    if length < 2:
        return
    splits = partition_int(length, random.randrange(2, 1 + min(length, 8)))
    if allow_also_not_np:
        write_linux_testvec_field(f, "also_non_np", 1)
    write_linux_testvec_field(f, "np", len(splits))
    taplist = ', '.join(str(split) for split in splits)
    write_linux_testvec_field(f, "tap", f"{{ {taplist} }}")

def write_linux_cipher_testvec(f, vec):
    """Format a cipher test vector for Linux's crypto tests."""
    write_linux_testvec_hexfield(f, "key", vec['input']['key'])
    write_linux_testvec_field(f, "klen", len(vec['input']['key']))
    write_linux_testvec_hexfield(f, "iv", vec['input']['tweak'])
    write_linux_testvec_hexfield(f, "ptext", vec['plaintext'])
    write_linux_testvec_hexfield(f, "ctext", vec['ciphertext'])
    length = len(vec['plaintext'])
    write_linux_testvec_field(f, "len", length)
    write_scatterlist_splits(f, length, True)

def write_linux_hash_testvec(f, vec):
    """Format a hash test vector for Linux's crypto tests."""
    write_linux_testvec_hexfield(f, "key", vec['input']['key'])
    write_linux_testvec_field(f, "ksize", len(vec['input']['key']))
    write_linux_testvec_hexfield(f, "plaintext", vec['input']['message'])
    length = len(vec['input']['message'])
    write_linux_testvec_field(f, "psize", length)
    write_linux_testvec_hexfield(f, "digest", vec['hash'])
    write_scatterlist_splits(f, length, False)

def sample_adiantum_testvecs(all_vecs):
    """Select some Adiantum test vectors to include in Linux's crypto tests."""
    have_lens = set()
    for vec in all_vecs:

        # Linux's crypto API supports only one tweak length per cipher.  We've
        # chosen 32 bytes, so exclude tests for other tweak lengths.
        if len(vec['input']['tweak']) != 32:
            continue

        # There isn't room for a huge number of test vectors, so just use one of
        # the "random" tests for each length that was generated.
        if 'Random' not in vec['description']:
            continue
        length = len(vec['plaintext'])
        if length in have_lens:
          continue

        have_lens.add(length)
        yield vec

def convert_hbsh_testvec(v):
    return {
        'key': v['input']['key'],
        'tweak': v['input']['tweak'],
        'plaintext': v['plaintext'],
        'ciphertext': v['ciphertext'],
    }

def hpc_vectors(variant, nrounds):
    yield from hexjson.iter_unhex(topdir / "test_vectors" / "ours" / variant /
        f'{variant}_XChaCha{nrounds}_32_AES256.json')

def hbsh(variant):
    """Convert test vectors for the given HBSH variant."""

    target = targetdir / f"{variant.lower()}_testvecs.h"
    with target.open("w") as f:
        f.write("/* GENERATED BY convert_testvecs.py, DO NOT EDIT */\n\n")
        for nrounds in [20, 12, 8]:
            write_testvec_structs(f, 'hbsh_testvec',
                f'{variant.lower()}_xchacha{nrounds}_aes256_tv',
                (convert_hbsh_testvec(s) for s in hpc_vectors(variant, nrounds)))

def hbsh_linux(variant):
    # Optionally format Adiantum's test vectors for the Linux kernel's crypto tests.
    target = targetdir / f"{variant.lower()}_testvecs_linux.h"
    with target.open("w") as f:
        for nrounds in [12, 20]:
            write_linux_testvecs(f, "cipher_testvec",
                f'hbsh_xchacha{nrounds}_aes_nhpoly1305',
                write_linux_cipher_testvec,
                sample_adiantum_testvecs(hpc_vectors(variant, nrounds)))

def convert_nh_testvec(v):
    return {
        'key': v['input']['key'],
        'message': v['input']['message'],
        'hash': v['hash'],
    }

def nh():
    """Convert the NH test vectors."""
    vectors = topdir / "test_vectors" / "ours" / "NH"
    target = targetdir / "nh_testvecs.h"
    with target.open("w") as f:
        f.write("/* GENERATED BY convert_testvecs.py, DO NOT EDIT */\n\n")
        vectorfile = vectors / f'NH.json'
        write_testvec_structs(f, 'nh_testvec', 'nh_tv',
            (convert_nh_testvec(s) for s in hexjson.iter_unhex(vectorfile)))

def sample_nhpoly1305_testvecs(all_vecs):
    have_lens = set()
    for vec in all_vecs:
        if 'Random' not in vec['description']:
            continue
        length = len(vec['input']['message'])
        if length in have_lens:
          continue
        have_lens.add(length)
        yield vec

def nhpoly1305_linux():
    vectors = topdir / "test_vectors" / "ours" / "NHPoly1305"
    target = targetdir / "nhpoly1305_testvecs_linux.h"
    with target.open("w") as f:
        vectorfile = vectors / f'NHPoly1305.json'
        write_linux_testvecs(f, "hash_testvec", 'nhpoly1305',
            write_linux_hash_testvec,
            sample_nhpoly1305_testvecs(hexjson.iter_unhex(vectorfile)))

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--linux', action='store_true')
    return p.parse_args()

def main():
    random.seed(0)
    args = parse_args()
    hbsh('HPolyC')
    hbsh('Adiantum')
    nh()
    if args.linux:
        hbsh_linux('Adiantum')
        nhpoly1305_linux()

if __name__ == "__main__":
    main()
