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

import os.path

import atheris_no_libfuzzer as atheris
from rules_fuzzing.examples.py import native_runfile
from rules_python.python.runfiles import runfiles

def test_one_input(data):
    fdp = atheris.FuzzedDataProvider(data)
    if fdp.ConsumeBool():
        load_python_runfile()
    else:
        native_runfile.load_cpp_runfile()

def load_python_runfile():
    r = runfiles.Create()
    runfile = r.Rlocation("rules_fuzzing/examples/py/corpus_0.txt")
    if not runfile or not os.path.isfile(runfile):
        raise RuntimeError("Python runfile not found!")
