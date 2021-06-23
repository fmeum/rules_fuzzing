# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Contains the external dependencies."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("//fuzzing/private/oss_fuzz:repository.bzl", "oss_fuzz_repository")

def rules_fuzzing_dependencies(
        oss_fuzz = True,
        honggfuzz = True,
        jazzer = False,
        atheris = False):
    """Instantiates the dependencies of the fuzzing rules.

    Args:
      oss_fuzz: Include OSS-Fuzz dependencies.
      honggfuzz: Include Honggfuzz dependencies.
      jazzer: Include Jazzer repository. Instantiating all Jazzer dependencies
        additionally requires invoking jazzer_dependencies() in
        @jazzer//:repositories.bzl and jazzer_init() in @jazzer//:init.bzl.
      atheris: Include Atheris repository.
    """

    maybe(
        http_archive,
        name = "rules_python",
        url = "https://github.com/bazelbuild/rules_python/releases/download/0.3.0/rules_python-0.3.0.tar.gz",
        sha256 = "934c9ceb552e84577b0faf1e5a2f0450314985b4d8712b2b70717dc679fdc01b",
    )
    maybe(
        http_archive,
        name = "bazel_skylib",
        urls = [
            "https://github.com/bazelbuild/bazel-skylib/releases/download/1.0.3/bazel-skylib-1.0.3.tar.gz",
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.0.3/bazel-skylib-1.0.3.tar.gz",
        ],
        sha256 = "1c531376ac7e5a180e0237938a2536de0c54d93f5c278634818e0efc952dd56c",
    )
    maybe(
        http_archive,
        name = "com_google_absl",
        urls = ["https://github.com/abseil/abseil-cpp/archive/4611a601a7ce8d5aad169417092e3d5027aa8403.zip"],
        strip_prefix = "abseil-cpp-4611a601a7ce8d5aad169417092e3d5027aa8403",
        sha256 = "f4f2d3d01c3cc99eebc9f370ea626c43a54b386913aef393bf8201b2c42a9e2f",
    )

    if oss_fuzz:
        maybe(
            oss_fuzz_repository,
            name = "rules_fuzzing_oss_fuzz",
        )

    if honggfuzz:
        maybe(
            http_archive,
            name = "honggfuzz",
            build_file = "@rules_fuzzing//:honggfuzz.BUILD",
            sha256 = "a6f8040ea62e0f630737f66dce46fb1b86140f118957cb5e3754a764de7a770a",
            url = "https://github.com/google/honggfuzz/archive/e0670137531242d66c9cf8a6dee677c055a8aacb.zip",
            strip_prefix = "honggfuzz-e0670137531242d66c9cf8a6dee677c055a8aacb",
        )

    if jazzer:
        maybe(
            http_archive,
            name = "jazzer",
            sha256 = "cf41aca8fbfb6904951e88bb8df1d0fc743396577bcb39c4f5a2408329061e37",
            strip_prefix = "jazzer-316da57a8688470fcfd5521673239b5fa66512ba",
            url = "https://github.com/CodeIntelligenceTesting/jazzer/archive/316da57a8688470fcfd5521673239b5fa66512ba.zip",
        )

    if atheris:
        maybe(
            http_archive,
            name = "atheris",
            build_file = "@rules_fuzzing//:atheris.BUILD",
            sha256 = "5b2fd9d32cb44877a2e3eebd2b97e76f4a9c6a6c27ea37752a4a33be732d8d5d",
            strip_prefix = "atheris-9169b8d1dd0a6ff66a7e87fc2f24cc87ff6c65df",
            url = "https://github.com/google/atheris/archive/9169b8d1dd0a6ff66a7e87fc2f24cc87ff6c65df.tar.gz",
        )

        maybe(
            http_archive,
            name = "pybind11_bazel",
            sha256 = "8f546c03bdd55d0e88cb491ddfbabe5aeb087f87de2fbf441391d70483affe39",
            strip_prefix = "pybind11_bazel-26973c0ff320cb4b39e45bc3e4297b82bc3a6c09",
            url = "https://github.com/pybind/pybind11_bazel/archive/26973c0ff320cb4b39e45bc3e4297b82bc3a6c09.tar.gz",
        )

        maybe(
            http_archive,
            name = "pybind11",
            build_file = "@pybind11_bazel//:pybind11.BUILD",
            sha256 = "8ff2fff22df038f5cd02cea8af56622bc67f5b64534f1b83b9f133b8366acff2",
            strip_prefix = "pybind11-2.6.2",
            url = "https://github.com/pybind/pybind11/archive/v2.6.2.tar.gz",
        )

        maybe(
            http_archive,
            name = "atheris_libfuzzer",
            build_file = "@rules_fuzzing//:atheris_libfuzzer.BUILD",
            sha256 = "8e6c99e482bb16a450165176c2d881804976a2d770e0445af4375e78a1fbf19c",
            strip_prefix = "llvm-project-llvmorg-12.0.0/compiler-rt/lib/fuzzer",
            url = "https://github.com/llvm/llvm-project/archive/llvmorg-12.0.0.tar.gz",
        )
