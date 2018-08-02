# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
