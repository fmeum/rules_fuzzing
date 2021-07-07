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
load("//fuzzing/private/sanitizer_libs:repository.bzl", "sanitizer_libs_repository")

def rules_fuzzing_dependencies(oss_fuzz = True, honggfuzz = True, jazzer = False):
    """Instantiates the dependencies of the fuzzing rules.

    Args:
      oss_fuzz: Include OSS-Fuzz dependencies.
      honggfuzz: Include Honggfuzz dependencies.
      jazzer: Include Jazzer repository. Instantiating all Jazzer dependencies
        additionally requires invoking jazzer_dependencies() in
        @jazzer//:repositories.bzl and jazzer_init() in @jazzer//:init.bzl.
    """

    maybe(
        http_archive,
        name = "rules_python",
        urls = [
            "https://github.com/bazelbuild/rules_python/releases/download/0.3.0/rules_python-0.3.0.tar.gz",
            "https://mirror.bazel.build/github.com/bazelbuild/rules_python/releases/download/0.3.0/rules_python-0.3.0.tar.gz",
        ],
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

        maybe(
            sanitizer_libs_repository,
            name = "rules_fuzzing_sanitizer_libs",
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
            sha256 = "c8d187663365f625bb00d6b531ede17898d87bbaed59de16a85590117cff0fa4",
            strip_prefix = "jazzer-1b11bd6515a65f02a1cbe5aaa183180faa92a55b",
            url = "https://github.com/CodeIntelligenceTesting/jazzer/archive/1b11bd6515a65f02a1cbe5aaa183180faa92a55b.zip",
        )
