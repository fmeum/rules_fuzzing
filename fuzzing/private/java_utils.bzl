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

"""Utilities and helper rules for Java fuzz tests."""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("//fuzzing/private:binary.bzl", "fuzzing_binary_transition")
load(
    "//fuzzing/private:instrum_opts.bzl",
    "instrum_defaults",
    "instrum_opts",
)
load(
    "//fuzzing:instrum_opts.bzl",
    "sanitizer_configs",
)
load("//fuzzing/private:util.bzl", "runfile_path")

# A Starlark reimplementation of a part of Bazel's JavaCommon#determinePrimaryClass.
def determine_primary_class(srcs, name):
    main_source_path = _get_java_main_source_path(srcs, name)
    return _get_java_full_classname(main_source_path)

# A Starlark reimplementation of a part of Bazel's JavaCommon#determinePrimaryClass.
def _get_java_main_source_path(srcs, name):
    main_source_basename = name + ".java"
    for source_file in srcs:
        if source_file[source_file.rfind("/") + 1:] == main_source_basename:
            main_source_basename = source_file
            break
    return native.package_name() + "/" + main_source_basename[:-len(".java")]

# A Starlark reimplementation of Bazel's JavaUtil#getJavaFullClassname.
def _get_java_full_classname(main_source_path):
    java_path = _get_java_path(main_source_path)
    if java_path != None:
        return java_path.replace("/", ".")
    return None

# A Starlark reimplementation of Bazel's JavaUtil#getJavaPath.
def _get_java_path(main_source_path):
    path_segments = main_source_path.split("/")
    index = _java_segment_index(path_segments)
    if index >= 0:
        return "/".join(path_segments[index + 1:])
    return None

_KNOWN_SOURCE_ROOTS = ["java", "javatests", "src", "testsrc"]

# A Starlark reimplementation of Bazel's JavaUtil#javaSegmentIndex.
def _java_segment_index(path_segments):
    root_index = -1
    for pos, segment in enumerate(path_segments):
        if segment in _KNOWN_SOURCE_ROOTS:
            root_index = pos
            break
    if root_index == -1:
        return root_index

    is_src = "src" == path_segments[root_index]
    check_maven_index = root_index if is_src else -1
    max = len(path_segments) - 1
    if root_index == 0 or is_src:
        for i in range(root_index + 1, max):
            segment = path_segments[i]
            if "src" == segment or (is_src and ("javatests" == segment or "java" == segment)):
                next = path_segments[i + 1]
                if ("com" == next or "org" == next or "net" == next):
                    root_index = i
                elif "src" == segment:
                    check_maven_index = i
                break

    if check_maven_index >= 0 and check_maven_index + 2 < len(path_segments):
        next = path_segments[check_maven_index + 1]
        if "main" == next or "test" == next:
            next = path_segments[check_maven_index + 2]
            if "java" == next or "resources" == next:
                root_index = check_maven_index + 2

    return root_index

def _jazzer_fuzz_binary_script(ctx):
    script = ctx.actions.declare_file(ctx.label.name)

    script_template = """#!/bin/bash
# --- begin runfiles.bash initialization v2 ---
# Copy-pasted from the Bazel Bash runfiles library v2 and escaped for Python format().
set -uo pipefail; f=bazel_tools/tools/bash/runfiles/runfiles.bash
source "${{RUNFILES_DIR:-/dev/null}}/$f" 2>/dev/null || \
 source "$(grep -sm1 "^$f " "${{RUNFILES_MANIFEST_FILE:-/dev/null}}" | cut -f2- -d' ')" 2>/dev/null || \
 source "$0.runfiles/$f" 2>/dev/null || \
 source "$(grep -sm1 "^$f " "$0.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \
 source "$(grep -sm1 "^$f " "$0.exe.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \
 {{ echo>&2 "ERROR: cannot find $f"; exit 1; }}; f=; set -e
# --- end runfiles.bash initialization v2 ---
# LLVMFuzzerTestOneInput - OSS-Fuzz needs this string literal
# to appear somewhere in the script so it is recognized as a
# fuzz target.
exec "$(rlocation {driver})" \
    --cp="$(rlocation {deploy_jar})" \
    --jvm_args="-Djava.library.path={library_path}" \
    "$@"
"""

    # Perform feature detection for
    # https://github.com/bazelbuild/bazel/commit/381a519dfc082d4c62096c4ce77ead1c2e0410d8.
    target_info = ctx.attr.target[0][JavaInfo]
    if "transitive_native_libraries" in dir(target_info):
        # The current version of Bazel contains the commit, which means that
        # the JavaInfo of the target includes information about all transitive
        # native library dependencies.
        native_libraries_list = target_info.transitive_native_libraries.to_list()
        native_paths = [
            lib.dynamic_library.short_path
            for lib in native_libraries_list
        ]
    else:
        # Fall back to the list of native library dependencies specified by the user.
        native_files = [
            native_dep[DefaultInfo].files
            for native_dep in ctx.attr.transitive_native_deps
        ]
        native_paths = [
            file.short_path
            for file in depset(transitive = native_files).to_list()
        ]
    native_dirs = [path[:path.rfind("/")] for path in native_paths]

    script_content = script_template.format(
        driver = runfile_path(ctx, ctx.executable.driver),
        deploy_jar = runfile_path(ctx, ctx.file.target_deploy_jar),
        library_path = ":".join(native_dirs),
        # If used within rules_fuzzing, the workspace_name of the binary can be
        # the empty string (it is "__main__" when used from another workspace
        # with no name).
        workdir = ctx.label.workspace_name or ctx.workspace_name,
    )
    print(script_content)
    ctx.actions.write(script, script_content, is_executable = True)
    return script

def _is_required_runfile(target, runtime_classpath, runfile):
    # The jars in the runtime classpath are all merged into the deploy jar and
    # thus don't need to be included in the runfiles for the fuzzer.
    if runfile in runtime_classpath:
        return False

    # A java_binary target has a dependency on the local JDK. Since the Jazzer
    # driver launches its own JVM, these runfiles are not needed.
    if runfile.owner != None and runfile.owner.workspace_name == "local_jdk":
        return False
    return True

def _filter_target_runfiles(ctx, target):
    compilation_info = target[JavaInfo].compilation_info
    runtime_classpath = compilation_info.runtime_classpath.to_list()
    all_runfiles = target[DefaultInfo].default_runfiles
    return ctx.runfiles([
        runfile
        for runfile in all_runfiles.files.to_list()
        if _is_required_runfile(target, runtime_classpath, runfile)
    ])

def _jazzer_fuzz_binary_impl(ctx):
    script = _jazzer_fuzz_binary_script(ctx)

    runfiles = ctx.runfiles()
    runfiles = runfiles.merge(ctx.attr.driver[DefaultInfo].default_runfiles)
    runfiles = runfiles.merge(ctx.runfiles([ctx.file._agent]))
    runfiles = runfiles.merge(ctx.runfiles([ctx.file._bash_runfiles_lib]))
    runfiles = runfiles.merge(_filter_target_runfiles(ctx, ctx.attr.target[0]))
    runfiles = runfiles.merge(ctx.runfiles([ctx.file.target_deploy_jar]))
    for native_dep in ctx.attr.transitive_native_deps:
        runfiles = runfiles.merge(native_dep[DefaultInfo].default_runfiles)
    return [DefaultInfo(executable = script, runfiles = runfiles)]

jazzer_fuzz_binary = rule(
    implementation = _jazzer_fuzz_binary_impl,
    doc = """
Rule that creates a binary that invokes Jazzer on the specified target.
""",
    attrs = {
        "_agent": attr.label(
            default = Label("@jazzer//agent:jazzer_agent_deploy.jar"),
            doc = "The Jazzer agent used to instrument the target.",
            allow_single_file = [".jar"],
        ),
        "_bash_runfiles_lib": attr.label(
            default = Label("@bazel_tools//tools/bash/runfiles"),
            allow_single_file = [".bash"],
        ),
        "driver": attr.label(
            default = Label("@jazzer//driver:jazzer_driver"),
            doc = "The Jazzer driver binary used to fuzz the target.",
            executable = True,
            # Build in target configuration rather than host because the driver
            # uses transitions to set the correct C++ standard for its
            # dependencies.
            cfg = "target",
        ),
        "transitive_native_deps": attr.label_list(
            doc = "The native libraries the fuzz target transitively depends " +
                  "on. The libraries are automatically instrumented for " +
                  "fuzzing.",
            providers = [CcInfo],
            cfg = fuzzing_binary_transition,
        ),
        "target": attr.label(
            doc = "The fuzz target.",
            mandatory = True,
            providers = [JavaInfo],
            cfg = fuzzing_binary_transition,
        ),
        "target_deploy_jar": attr.label(
            doc = "The deploy jar of the fuzz target.",
            allow_single_file = [".jar"],
            mandatory = True,
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    executable = True,
)
