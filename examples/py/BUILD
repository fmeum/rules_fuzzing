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

# Simple fuzz targets that demonstrate the Bazel extension functionality and
# serve as regression tests. Targets that are expected to crash or hang are
# disabled in the OSS-Fuzz integration using the "no-oss-fuzz" tag.

load("@pybind11_bazel//:build_defs.bzl", "pybind_extension")
load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//fuzzing:py_defs.bzl", "py_fuzz_test")

py_fuzz_test(
    name = "empty_fuzz_test",
    srcs = ["empty_fuzz_test.py"],
)

py_fuzz_test(
    name = "fuzz_test",
    srcs = ["fuzz_test.py"],
    tags = [
        "no-oss-fuzz",
    ],
)

py_fuzz_test(
    name = "native_fuzz_test",
    srcs = ["native_fuzz_test.py"],
    data = [
        ":native",
    ],
    tags = [
        "no-oss-fuzz",
    ],
)

py_fuzz_test(
    name = "native_runfile_fuzz_test",
    srcs = ["native_runfile_fuzz_test.py"],
    data = [
        "corpus_0.txt",
        ":native_runfile.so",
    ],
    deps = [
        "@rules_python//python/runfiles",
    ],
)

cc_binary(
    name = "native",
    srcs = [
        "native.c",
    ],
    linkshared = 1,
)

pybind_extension(
    name = "native_runfile",
    srcs = [
        "native_runfile.cpp",
    ],
    data = [
        "corpus_1.txt",
    ],
    deps = [
        "@bazel_tools//tools/cpp/runfiles",
    ],
)
