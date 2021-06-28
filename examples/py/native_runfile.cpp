// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <fstream>
#include <iostream>
#include <string>

#include "pybind11/pybind11.h"
#include "tools/cpp/runfiles/runfiles.h"

namespace native_runfile {
void load_cpp_runfile() {
  using ::bazel::tools::cpp::runfiles::Runfiles;
  std::string error;
  Runfiles *runfiles = Runfiles::Create("", &error);
  if (runfiles == nullptr) {
    std::cerr << error;
    abort();
  }
  std::string path =
      runfiles->Rlocation("rules_fuzzing/examples/py/corpus_1.txt");
  if (path.empty()) abort();
  std::ifstream in(path);
  if (!in.good()) abort();
}

PYBIND11_MODULE(native_runfile, m) {
  m.def("load_cpp_runfile", &load_cpp_runfile);
}
}
