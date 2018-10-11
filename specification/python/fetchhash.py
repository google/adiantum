# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import hashlib

import requests

def do_fetch_file(path, url):
    r = requests.get(url, stream=True)
    r.raise_for_status()
    with path.open("wb") as f:
        for chunk in r.iter_content(4096):
            f.write(chunk)

def hash_file(path):
    m = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            m.update(data)
    return m.hexdigest()

def fetch_file(path, url, expected_hash):
    if path.exists():
        h = hash_file(path)
        if h == expected_hash:
            return
        path.unlink()
    print(f"Downloading: {url}")
    do_fetch_file(path, url)
    got = hash_file(path)
    if got != expected_hash:
        raise Exception(f"Hash mismatch, expected {expected_hash} but got {got}")
