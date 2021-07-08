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
load(
    "//fuzzing/private:util.bzl",
    "FUZZER_RUNNER_SCRIPT_PROLOGUE",
    "generate_file",
    "runfile_path",
)

ATHERIS_FUZZ_TARGET_WRAPPER = """import sys

import atheris_no_libfuzzer as atheris

import {target_module}

atheris.Setup(sys.argv, {target_module}.test_one_input)
atheris.Fuzz()
"""

def atheris_fuzz_target(
        name,
        target_module,
        **library_kwargs):
    """Defines a `py_binary` wrapper that sets up and runs Atheris.

    The provided library arguments are used to define a `py_library` target,
    which is then added as a dependency to a `py_binary` that imports the
    `target_module` and sets up fuzzing with Atheris for the test_one_input
    method in that module.

    Args:
        name: A unique name for this target. Required.
        target_module: The module that contains the test_one_input method.
          Required.
        **library_kwargs: Keyword arguments directly forwarded to the fuzz test
          `py_library` rule.
    """
    wrapper_py_name = name + ".py"
    wrapper_py_gen_name = name + "_py_gen_"
    library_name = name + "_lib_"

    generate_file(
        name = wrapper_py_gen_name,
        contents = ATHERIS_FUZZ_TARGET_WRAPPER.format(
            target_module = target_module,
        ),
        output = wrapper_py_name,
    )

    # Lets the wrapper import the actual target just knowing its filename. This
    # is needed since a Starlark macro has now way to get the name of the main
    # workspace.
    library_kwargs.setdefault("imports", []).append(".")

    # Lets the target use Atheris' FuzzedDataProvider.
    library_kwargs.setdefault("deps", []).append(
        "@atheris//:atheris_no_libfuzzer",
    )
    native.py_library(
        name = library_name,
        **library_kwargs
    )

    native.py_binary(
        name = name,
        srcs = [
            ":" + wrapper_py_gen_name,
        ],
        main = wrapper_py_name,
        deps = [
            ":" + library_name,
            "@atheris//:atheris_no_libfuzzer",
        ],
    )

def _python_fuzzer_runner_script(ctx):
    script = ctx.actions.declare_file(ctx.label.name)

    # The script is split into two parts: The first is emitted as-is, the second
    # is a template that is passed to format(). Without the split, curly braces
    # in the first part would need to be escaped.
    script_literal_part = FUZZER_RUNNER_SCRIPT_PROLOGUE
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

def _python_fuzzer_runner_impl(ctx):
    runfiles = ctx.runfiles()

    # Used by the wrapper script created in _python_fuzzer_runner_script.
    runfiles = runfiles.merge(ctx.attr._bash_runfiles_library[DefaultInfo].default_runfiles)
    runfiles = runfiles.merge(ctx.attr.target[0][DefaultInfo].default_runfiles)
    runfiles = runfiles.merge(ctx.runfiles([ctx.file.sanitizer_options]))
    runfiles = runfiles.merge(ctx.runfiles([ctx.file.sanitizer_with_fuzzer]))

    script = _python_fuzzer_runner_script(ctx)
    return [DefaultInfo(executable = script, runfiles = runfiles)]

python_fuzzer_runner = rule(
    implementation = _python_fuzzer_runner_impl,
    doc = """
Rule that creates a binary that invokes a Python fuzzer.
""",
    attrs = {
        "_bash_runfiles_library": attr.label(
            default = "@bazel_tools//tools/bash/runfiles",
        ),
        "sanitizer_options": attr.label(
            doc = "A shell script that can export environment variables with " +
                  "sanitizer options.",
            allow_single_file = [".sh"],
        ),
        "sanitizer_with_fuzzer": attr.label(
            doc = "A shared library containing libFuzzer and the statically " +
                  "linked sanitizer runtime.",
            allow_single_file = [".so"],
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
