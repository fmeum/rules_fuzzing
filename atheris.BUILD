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

# Bazel rules for building the Atheris Python extension. libFuzzer is not linked
# in statically, but preloaded as a dynamic library together with the sanitizer,
# (see @libfuzzer).

load("@pybind11_bazel//:build_defs.bzl", "pybind_extension", "pybind_library")
load("@rules_fuzzing//fuzzing/private:binary.bzl", "cc_wrapper_no_instrumentation")

# This library cannot be used directly as it would be instrumented for fuzzing,
# which hurts performance.
pybind_library(
    name = "atheris_no_libfuzzer_lib_do_not_use_",
    srcs = [
        "atheris.cc",
        "atheris.h",
        "fuzzed_data_provider.cc",
        "fuzzed_data_provider.h",
        "libfuzzer.cc",
        "macros.h",
        "tracer.cc",
        "tracer.h",
        "util.cc",
        "util.h",
    ],
    linkstatic = True,
    local_defines = [
        "ATHERIS_MODULE_NAME=atheris_no_libfuzzer",
    ],
    alwayslink = True,
)

# Prevents fuzzing instrumentation from being applied by using a second
# transition.
cc_wrapper_no_instrumentation(
    name = "atheris_no_libfuzzer_lib",
    original = ":atheris_no_libfuzzer_lib_do_not_use_",
)

# This macro generates a cc_binary target with name atheris_no_libfuzzer.so,
# which has to match both the ATHERIS_MODULE_NAME set on the lib target as well
# as the name of the Python library that wraps this native extension.
pybind_extension(
    name = "atheris_no_libfuzzer",
    deps = [
        ":atheris_no_libfuzzer_lib",
    ],
)

py_library(
    name = "atheris_no_libfuzzer",
    data = [
        ":atheris_no_libfuzzer.so",
    ],
    # Makes is possible to import this library just like Atheris obtained via
    # pip:
    #   import atheris_no_libfuzzer
    imports = ["."],
    visibility = ["//visibility:public"],
)
