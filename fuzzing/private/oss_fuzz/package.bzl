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

"""Rule for packaging fuzz tests in the expected OSS-Fuzz format."""

load("//fuzzing/private:binary.bzl", "FuzzingBinaryInfo")

def _oss_fuzz_package_impl(ctx):
    output_archive = ctx.actions.declare_file(ctx.label.name + ".tar")
    base_name = ctx.attr.base_name
    binary_info = ctx.attr.binary[FuzzingBinaryInfo]
    binary_path = binary_info.binary_file.path
    binary_short_path = binary_info.binary_file.short_path
    binary_workdir = "{base_name}.runfiles/{binary_workspace}".format(
        base_name = base_name,
        binary_workspace = binary_info.binary_workspace,
    )

    # Create a wrapper that executes the actual fuzz test binary with the
    # working directory set to what it would be in the Bazel runfiles tree.
    # Note: ClusterFuzz may execute fuzz tests with a working directory
    # different from the containing directory.
    launcher = ctx.actions.declare_file(ctx.label.name + "_launcher.sh")
    launcher_script = """#!/bin/sh
echo "this_dir=$(dirname "$0")
# Allow the Bazel runfiles libraries to find the tree.
export RUNFILES_DIR=$(readlink -f "$this_dir/{base_name}.runfiles")
# LLVMFuzzerTestOneInput - OSS-Fuzz needs this string literal
# to appear somewhere in the script so it is recognized as a
# fuzz target.
cd $this_dir/{binary_workdir}
exec {binary_short_path} $@"
"""
    ctx.actions.write(launcher, launcher_script.format(
        base_name = base_name,
        binary_short_path = binary_short_path,
        binary_workdir = binary_workdir,
    ), True)
    archive_inputs = [launcher]

    binary_runfiles = binary_info.binary_runfiles.files.to_list()
    binary_runfiles_snippet = """
    mkdir -p "$(dirname "$STAGING_DIR/{binary_workdir}/{runfile_short_path}")"
    ln -s "$(pwd)/{runfile_path}" "$STAGING_DIR/{binary_workdir}/{runfile_short_path}"
    """
    binary_runfiles_script = "".join([
        binary_runfiles_snippet.format(
            binary_workdir = binary_workdir,
            runfile_path = runfile.path,
            runfile_short_path = runfile.short_path,
        )
        for runfile in binary_runfiles
    ])
    archive_inputs += binary_runfiles

    if binary_info.corpus_dir:
        archive_inputs.append(binary_info.corpus_dir)
    if binary_info.dictionary_file:
        archive_inputs.append(binary_info.dictionary_file)
    ctx.actions.run_shell(
        outputs = [output_archive],
        inputs = archive_inputs,
        command = """
            set -e
            declare -r STAGING_DIR="$(mktemp --directory -t oss-fuzz-pkg.XXXXXXXXXX)"
            function cleanup() {{
                rm -rf "$STAGING_DIR"
            }}
            trap cleanup EXIT
            {binary_runfiles_script}
            ln -s "$(pwd)/{launcher_path}" "$STAGING_DIR/{base_name}"
            if [[ -n "{corpus_dir}" ]]; then
                pushd "{corpus_dir}" >/dev/null
                zip --quiet -r "$STAGING_DIR/{base_name}_seed_corpus.zip" ./*
                popd >/dev/null
            fi
            if [[ -n "{dictionary_path}" ]]; then
                ln -s "$(pwd)/{dictionary_path}" "$STAGING_DIR/{base_name}.dict"
            fi
            if [[ -n "{options_path}" ]]; then
                ln -s "$(pwd)/{options_path}" "$STAGING_DIR/{base_name}.options"
            fi
            tar -chf "{output}" -C "$STAGING_DIR" .
        """.format(
            base_name = base_name,
            binary_runfiles_script = binary_runfiles_script,
            corpus_dir = binary_info.corpus_dir.path if binary_info.corpus_dir else "",
            dictionary_path = binary_info.dictionary_file.path if binary_info.dictionary_file else "",
            launcher_path = launcher.path,
            options_path = binary_info.options_file.path if binary_info.options_file else "",
            output = output_archive.path,
        ),
    )
    return [DefaultInfo(files = depset([output_archive]))]

oss_fuzz_package = rule(
    implementation = _oss_fuzz_package_impl,
    doc = """
Packages a fuzz test in a TAR archive compatible with the OSS-Fuzz format.
""",
    attrs = {
        "binary": attr.label(
            executable = True,
            doc = "The fuzz test executable.",
            providers = [FuzzingBinaryInfo],
            mandatory = True,
            cfg = "target",
        ),
        "base_name": attr.string(
            doc = "The base name of the fuzz test used to form the file names " +
                  "in the OSS-Fuzz output.",
            mandatory = True,
        ),
    },
)
