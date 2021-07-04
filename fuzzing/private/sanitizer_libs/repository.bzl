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

"""Repository rule that provides cc_import targets for sanitizer libraries."""

def _get_machine_arch(repository_ctx):
    result = repository_ctx.execute(["uname", "-m"])
    if result.return_code != 0:
        fail("Could not obtain machine architecture: %s" % result.stderr)
    return result.stdout.strip()

def _compiler_rt_lib(name, arch):
    return "libclang_rt.%s-%s.a" % (name, arch)

def _find_llvm_config(repository_ctx):
    cc = repository_ctx.os.environ["CC"]
    cc_path = repository_ctx.which(cc)
    result = repository_ctx.execute([
        repository_ctx.which("bash"),
        "-c",
        """
            set -euf -o pipefail
            set -x
            dirname "$(readlink -f {cc_path})"
        """.format(
            cc_path = cc_path,
        ),
    ])
    cc_dir = result.stdout.strip()

    if result.return_code != 0 or not cc_dir:
        fail("Failed to resolve '%s': %s" % (cc_path, result.stderr))
    return cc_dir + "/llvm-config"

def _find_llvm_lib(repository_ctx, llvm_config, target_file):
    result = repository_ctx.execute([
        repository_ctx.which("bash"),
        "-c",
        """
            set -euf -o pipefail
            set -x
            find "$({llvm_config} --libdir)" -name {target_file} | head -1
        """.format(
            llvm_config = llvm_config,
            target_file = target_file,
        ),
    ], quiet = False)
    file_path = result.stdout.strip()

    if result.return_code != 0 or not file_path:
        fail("Could not find LLVM library '%s'" % target_file)
    return file_path

def _link_sanitizer_lib(repository_ctx, arch, llvm_config, sanitizer):
    lib_name = _compiler_rt_lib(sanitizer, arch)
    lib_path = _find_llvm_lib(repository_ctx, llvm_config, lib_name)
    repository_ctx.symlink(lib_path, sanitizer + ".a")

_CC_IMPORT_SANITIZER_LIB_TEMPLATE = """
cc_import(
    name = "{name}",
    static_library = "{name}.a",
    visibility = ["//visibility:public"],
    alwayslink = True,
)
"""

def _cc_import_sanitizer_lib(name):
    return _CC_IMPORT_SANITIZER_LIB_TEMPLATE.format(
        name = name,
    )

_SANITIZER_LIBS = [
    "asan",
    "ubsan_standalone_cxx",
]

def _sanitizer_libs_repository(repository_ctx):
    arch = _get_machine_arch(repository_ctx)
    llvm_config = _find_llvm_config(repository_ctx)

    sanitizer_lib_targets = ""
    for sanitizer_lib in _SANITIZER_LIBS:
        _link_sanitizer_lib(repository_ctx, arch, llvm_config, sanitizer_lib)
        sanitizer_lib_targets += _cc_import_sanitizer_lib(sanitizer_lib)

    repository_ctx.template(
        "BUILD",
        repository_ctx.path(Label("@rules_fuzzing//fuzzing/private/sanitizer_libs:BUILD.tpl")),
        {
            "%{sanitizer_lib_targets}": sanitizer_lib_targets,
        }
    )

sanitizer_libs_repository = repository_rule(
    implementation = _sanitizer_libs_repository,
    environ = ["CC"],
    configure = True,
    local = True,
)
