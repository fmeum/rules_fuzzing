# Copyright 2021 Google LLC
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

"""Utilities and helper rules for Python fuzz tests."""

load("//fuzzing/private:binary.bzl", "fuzzing_binary_transition")
load("//fuzzing/private:util.bzl", "generate_file", "runfile_path")

ATHERIS_FUZZ_TARGET_WRAPPER = """import sys
import atheris_no_libfuzzer as atheris

import {target_module}

atheris.Setup(sys.argv, {target_module}.test_one_input)
atheris.Fuzz()
"""

ATHERIS_FUZZ_TARGET_WRAPPER_WITH_PROVIDER = """import sys
import atheris.atheris_no_libfuzzer as atheris

import {target_module}

def test_one_input_fdp(data):
    fdp = atheris.FuzzedDataProvider(data)
    {target_module}.test_one_input(fdp)

atheris.Setup(sys.argv, test_one_input_fdp)
atheris.Fuzz()
"""

def atheris_fuzz_target_wrapper(
        name,
        engine_lib,
        target_module,
        use_fuzzed_data_provider,
        **library_kwargs):
    wrapper_name = name
    wrapper_py_name = wrapper_name + ".py"
    wrapper_py_gen_name = wrapper_name + "_py_gen_"
    library_name = name + "_lib_"

    if use_fuzzed_data_provider:
        wrapper_template = ATHERIS_FUZZ_TARGET_WRAPPER_WITH_PROVIDER
    else:
        wrapper_template = ATHERIS_FUZZ_TARGET_WRAPPER

    generate_file(
        name = wrapper_py_gen_name,
        contents = ATHERIS_FUZZ_TARGET_WRAPPER.format(
            target_module = target_module,
        ),
        output = wrapper_py_name,
    )

    library_kwargs.setdefault("imports", []).append(".")
    native.py_library(
        name = library_name,
        **library_kwargs
    )

    native.py_binary(
        name = wrapper_name,
        srcs = [
            ":" + wrapper_py_gen_name,
        ],
        main = wrapper_py_name,
        deps = [
            ":" + library_name,
            engine_lib,
        ],
    )

def _atheris_fuzz_binary_script(ctx):
    script = ctx.actions.declare_file(ctx.label.name)

    # The script is split into two parts: The first is emitted as-is, the second
    # is a template that is passed to format(). Without the split, curly braces
    # in the first part would need to be escaped.
    script_literal_part = """#!/bin/bash
# LLVMFuzzerTestOneInput - OSS-Fuzz needs this string literal to appear
# somewhere in the script so it is recognized as a fuzz target.

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

    script_format_part = """
source "$(rlocation {sanitizer_options})"
LD_PRELOAD="$(rlocation {sanitizer_with_fuzzer})" \
exec "$(rlocation {target})" "$@"
"""

    script_content = script_literal_part + script_format_part.format(
        target = runfile_path(ctx, ctx.executable.target),
        sanitizer_options = runfile_path(ctx, ctx.file.sanitizer_options),
        sanitizer_with_fuzzer = runfile_path(ctx, ctx.file.sanitizer_with_fuzzer),
    )
    ctx.actions.write(script, script_content, is_executable = True)
    return script

def _atheris_fuzz_binary_impl(ctx):
    runfiles = ctx.runfiles()

    # Used by the wrapper script created in _atheris_fuzz_binary_script.
    runfiles = runfiles.merge(ctx.attr._bash_runfiles_library[DefaultInfo].default_runfiles)
    runfiles = runfiles.merge(ctx.attr.target[0][DefaultInfo].default_runfiles)
    runfiles = runfiles.merge(ctx.runfiles([ctx.file.sanitizer_options]))
    runfiles = runfiles.merge(ctx.runfiles([ctx.file.sanitizer_with_fuzzer]))

    script = _atheris_fuzz_binary_script(ctx)
    return [DefaultInfo(executable = script, runfiles = runfiles)]

atheris_fuzz_binary = rule(
    implementation = _atheris_fuzz_binary_impl,
    doc = """
Rule that creates a binary that invokes Atheris on the specified target.
""",
    attrs = {
        "_bash_runfiles_library": attr.label(
            default = "@bazel_tools//tools/bash/runfiles",
        ),
        "sanitizer_with_fuzzer": attr.label(
            doc = "A shared library containing libFuzzer and the statically " +
                  "linked sanitizer runtime.",
            allow_single_file = [".so"],
        ),
        "sanitizer_options": attr.label(
            doc = "A shell script that can export environment variables with " +
                  "sanitizer options.",
            allow_single_file = [".sh"],
        ),
        "target": attr.label(
            doc = "The fuzz target.",
            mandatory = True,
            executable = True,
            providers = [PyInfo],
            cfg = fuzzing_binary_transition,
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    executable = True,
)
