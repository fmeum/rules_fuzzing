# Copyright 2023 Google LLC
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

"""Rule that extracts clang runtime libraries from the current cc_toolchain."""

load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")

def _clang_runtime_lib_impl(ctx):
    cc_toolchain = find_cc_toolchain(ctx)
    feature_configuration = cc_common.configure_features(
        ctx = ctx,
        cc_toolchain = cc_toolchain,
        requested_features = ctx.features,
        unsupported_features = ctx.disabled_features,
    )

    # Ask the linker driver for the runtime library the same way a link action
    # would invoke it rather than via $(CC): Toolchains may only make their
    # runtime libraries available to link actions (e.g. hermetic-llvm via
    # -resource-dir) and their tools may require environment variables set by
    # the toolchain (e.g. the compiler wrapper of apple_support).
    action_name = ACTION_NAMES.cpp_link_executable
    linker = cc_common.get_tool_for_action(
        feature_configuration = feature_configuration,
        action_name = action_name,
    )
    link_variables = cc_common.create_link_variables(
        feature_configuration = feature_configuration,
        cc_toolchain = cc_toolchain,
    )
    link_flags = cc_common.get_memory_inefficient_command_line(
        feature_configuration = feature_configuration,
        action_name = action_name,
        variables = link_variables,
    )
    env = dict(ctx.configuration.default_shell_env)
    env.update(cc_common.get_environment_variables(
        feature_configuration = feature_configuration,
        action_name = action_name,
        variables = link_variables,
    ))
    execution_requirements = {
        requirement: ""
        for requirement in cc_common.get_execution_requirements(
            feature_configuration = feature_configuration,
            action_name = action_name,
        )
    }

    output = ctx.actions.declare_file(ctx.attr.basenames[0])
    args = ctx.actions.args()
    args.add(output)
    args.add(linker)
    args.add_all(link_flags)
    ctx.actions.run_shell(
        outputs = [output],
        inputs = cc_toolchain.all_files,
        command = "\n".join(['out="$1"', "shift"] + [
            """cp -f "$("$@" --print-file-name {})" "$out" 2> /dev/null || true""".format(basename)
            for basename in ctx.attr.basenames
        ]),
        arguments = [args],
        env = env,
        execution_requirements = execution_requirements,
        mnemonic = "ClangRuntimeLib",
        progress_message = "Extracting clang runtime library %{output}",
    )
    return [DefaultInfo(files = depset([output]))]

clang_runtime_lib = rule(
    implementation = _clang_runtime_lib_impl,
    doc = """
Provides the first available clang runtime library with any of the given
basenames as output.

The basename of the output file is always the first of the given basenames.
""",
    attrs = {
        "basenames": attr.string_list(
            doc = "The basenames of the runtime library to look up.",
            mandatory = True,
            allow_empty = False,
        ),
    },
    fragments = ["cpp"],
    toolchains = use_cc_toolchain(),
)
