
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ctypes
import pathlib

libname = pathlib.Path().absolute() / "examples" / "py" / "libnative.so"
c_lib = ctypes.CDLL(libname)
c_lib.parse.argtypes = [ctypes.c_char_p, ctypes.c_size_t]

def test_one_input(data):
    c_lib.parse(data, len(data))
