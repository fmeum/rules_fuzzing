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

"""Miscellaneous utilities."""

load("@bazel_skylib//lib:paths.bzl", "paths")

FUZZER_RUNNER_SCRIPT_PROLOGUE = """#!/bin/bash
# LLVMFuzzerTestOneInput - OSS-Fuzz needs this string literal to appear
# somewhere in the script so it is recognized as a fuzz target.

# Bazel-provided code snippet that should be copy-pasted as is at use sites.
# Taken from @bazel_tools//tools/bash/runfiles.
# --- begin runfiles.bash initialization v2 ---
# Copy-pasted from the Bazel Bash runfiles library v2.
set -uo pipefail; f=bazel_tools/tools/bash/runfiles/runfiles.bash
source "${RUNFILES_DIR:-/dev/null}/$f" 2>/dev/null || \
source "$(grep -sm1 "^$f " "${RUNFILES_MANIFEST_FILE:-/dev/null}" | cut -f2- -d' ')" 2>/dev/null || \
source "$0.runfiles/$f" 2>/dev/null || \
source "$(grep -sm1 "^$f " "$0.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \
source "$(grep -sm1 "^$f " "$0.exe.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \
{ echo>&2 "ERROR: cannot find $f"; exit 1; }; f=; set -e
# --- end runfiles.bash initialization v2 ---

# Export the env variables required for subprocesses to find their runfiles.
runfiles_export_envvars
"""

def _generate_file_impl(ctx):
    ctx.actions.write(ctx.outputs.output, ctx.attr.contents)

generate_file = rule(
    implementation = _generate_file_impl,
    doc = """
Generates a file with a specified content string.
""",
    attrs = {
        "contents": attr.string(
            doc = "The file contents.",
            mandatory = True,
        ),
        "output": attr.output(
            doc = "The output file to write.",
            mandatory = True,
        ),
    },
)

# Returns the path of a runfile that can be used to look up its absolute path
# via the rlocation function provided by Bazel's runfiles libraries.
def runfile_path(ctx, runfile):
    return paths.normalize(ctx.workspace_name + "/" + runfile.short_path)
