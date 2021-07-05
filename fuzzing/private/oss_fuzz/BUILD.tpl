# Copyright 2020 Google LLC
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

load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzzing_engine")
load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_python//python:defs.bzl", "py_runtime", "py_runtime_pair")

cc_fuzzing_engine(
    name = "oss_fuzz_engine",
    display_name = "OSS-Fuzz",
    launcher = "oss_fuzz_launcher.sh",
    library = ":oss_fuzz_stub",
    visibility = ["//visibility:public"],
)

cc_library(
    name = "oss_fuzz_stub",
    srcs = [%{stub_srcs}],
    linkopts = [%{stub_linkopts}],
    deps = [%{stub_deps}],
)

filegroup(
    name = "python3_files",
    srcs = glob([
        "python3/**",
    ], exclude = [
        "python3/**/launcher manifest.xml",
        "python3/lib/python3.8/site-packages/setuptools/script (dev).tmpl",
    ]),
)

py_runtime(
    name = "python3_runtime",
    files = [":python3_files"],
    interpreter = "python3/bin/python3",
    python_version = "PY3",
)

py_runtime_pair(
    name = "python_runtime_pair",
    py3_runtime = ":python3_runtime",
)

toolchain(
    name = "python_toolchain",
    toolchain = ":python_runtime_pair",
    toolchain_type = "@bazel_tools//tools/python:toolchain_type",
)

exports_files([
    "instrum.bzl", %{exported_files}
])
