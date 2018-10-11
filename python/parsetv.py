# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import re

class ParseTv(object):
    def __init__(self):
        self._globalparams = {}
        self._tvkey = None
        self._tvvalue = None
        self._tvdict = None
        self._tvstreamlist = None
        self._tv = None
        self._tvlist = None
        self._tvset = None
        self._setlist = []
        self._result = []

    def parse_file(self, fpath):
        self._finish_setlist()
        with fpath.open() as f:
            for l in f:
                self._handle_line(l)
        self._finish_setlist()

    def get(self):
        return self._result

    def _vappend(self, v):
        self._tvvalue.append(v)

    def _start_tvkv(self, k):
        self._finish_tvkv()
        self._tvkey = k
        self._tvvalue = []

    def _finish_tv(self):
        self._finish_tvkv()
        if self._tvstreamlist:
            self._tv["dict"] = self._tvdict
            self._tv["streams"] = self._tvstreamlist
            self._tvlist.append(self._tv)
        self._tvdict = None
        self._tvstreamlist = None
        self._tv = None

    def _start_tv(self, d):
        self._finish_tv()
        self._tv = d
        self._tvdict = {}
        self._tvstreamlist = []

    def _finish_tvset(self):
        self._finish_tv()
        if self._tvlist:
            self._tvset["testvectors"] = self._tvlist
            self._setlist.append(self._tvset)
        self._tvlist = None
        self._tvset = None

    def _start_tvset(self, d):
        self._finish_tvset()
        self._tvset = d
        self._tvlist = []

    def _finish_setlist(self):
        self._finish_tvset()
        if self._setlist:
            self._result.append({
                "params": self._globalparams,
                "vectorsets": self._setlist,
            })
        self._globalparams = {}
        self._setlist = []
