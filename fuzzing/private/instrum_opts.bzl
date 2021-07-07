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

"""A representation for instrumentation options, along with operations."""

def _is_string_list(value):
    if type(value) != type([]):
        return False
    if any([type(element) != type("") for element in value]):
        return False
    return True

def _make_opts(
        copts = [],
        conlyopts = [],
        cxxopts = [],
        linkopts = []):
    """Creates new instrumentation options.

    The struct fields mirror the argument names of this function.

    Args:
      copts: A list of C/C++ compilation options passed as `--copt`
        configuration flags.
      conlyopts: A list of C-only compilation options passed as `--conlyopt`
        configuration flags.
      cxxopts: A list of C++-only compilation options passed as `--cxxopts`
        configuration flags.
      linkopts: A list of linker options to pass as `--linkopt`
        configuration flags.
    Returns:
      A struct with the given instrumentation options.
    """
    if not _is_string_list(copts):
        fail("copts should be a list of strings")
    if not _is_string_list(conlyopts):
        fail("conlyopts should be a list of strings")
    if not _is_string_list(cxxopts):
        fail("cxxopts should be a list of strings")
    if not _is_string_list(linkopts):
        fail("linkopts should be a list of strings")
    return struct(
        copts = copts,
        conlyopts = conlyopts,
        cxxopts = cxxopts,
        linkopts = linkopts,
    )

def _merge_opts(left_opts, right_opts):
    return _make_opts(
        copts = left_opts.copts + right_opts.copts,
        conlyopts = left_opts.conlyopts + right_opts.conlyopts,
        cxxopts = left_opts.cxxopts + right_opts.cxxopts,
        linkopts = left_opts.linkopts + right_opts.linkopts,
    )

# These no-op defines are used as delimiters that enclose the command-line
# options added for fuzzing instrumentation, which makes it possible to cleanly
# remove these options with a follow-up transition.
_INSTRUM_START_MARKER = "-D_BAZEL_RULES_FUZZING_INSTRUM_START_"
_INSTRUM_END_MARKER = "-D_BAZEL_RULES_FUZZING_INSTRUM_END_"

def _add_marker(opts, marker):
    return _make_opts(
        copts = opts.copts + [marker],
        conlyopts = opts.conlyopts + [marker],
        cxxopts = opts.cxxopts + [marker],
        linkopts = opts.linkopts + [marker],
    )

def _mark_start(opts):
    """Marks the start of instrumentation command-line options.

    To be used in conjunction with `mark_end` to later allow `drop_marked` to
    drop all options added between the calls to `mark_start` and `mark_end`.

    Args:
      opts: A struct with command-line options to which no fuzzing-related
        instrumentation options have been added yet.
    Return:
      A new struct with the same options as in `opts` and an additional start
      marker.
    """
    return _add_marker(opts, _INSTRUM_START_MARKER)

def _mark_end(opts):
    """Marks the end of instrumentation command-line options.

    To be used in conjunction with `mark_start` to later allow `drop_marked` to
    drop all options added between the calls to `mark_start` and `mark_end`.

    Args:
      opts: A struct with instrumentation options.
    Return:
      A new struct with the same options as in `opts` and an additional end
      marker.
    """
    return _add_marker(opts, _INSTRUM_END_MARKER)

def _drop_opts_between_markers(list):
    new_list = []
    take = True
    for opt in list:
        if opt == _INSTRUM_START_MARKER:
            take = False
        elif opt == _INSTRUM_END_MARKER:
            take = True
        elif take:
            new_list.append(opt)
    return new_list

def _drop_marked(opts):
    """Removes options added between calls to `mark_start` and `mark_end`.

    Args:
      opts: A struct with instrumentation options.
    Return:
      A new struct with all options removed that were added between calls to
      `mark_start` and `mark_end`.
    """
    return _make_opts(
        copts = _drop_opts_between_markers(opts.copts),
        conlyopts = _drop_opts_between_markers(opts.conlyopts),
        cxxopts = _drop_opts_between_markers(opts.cxxopts),
        linkopts = _drop_opts_between_markers(opts.linkopts),
    )

instrum_opts = struct(
    make = _make_opts,
    merge = _merge_opts,
    mark_start = _mark_start,
    mark_end = _mark_end,
    drop_marked = _drop_marked,
)

instrum_defaults = struct(
    # Instrumentation applied to all fuzz test executables when built in fuzzing
    # mode. This mode is controlled by the `//fuzzing:cc_fuzzing_build_mode`
    # config flag.
    fuzzing_build = _make_opts(
        copts = ["-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"],
    ),
    libfuzzer = _make_opts(
        copts = ["-fsanitize=fuzzer-no-link"],
    ),
    # Reflects the set of options at
    # https://github.com/google/honggfuzz/blob/master/hfuzz_cc/hfuzz-cc.c
    honggfuzz = _make_opts(
        copts = [
            "-mllvm",
            "-inline-threshold=2000",
            "-fno-builtin",
            "-fno-omit-frame-pointer",
            "-D__NO_STRING_INLINES",
            "-fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div,indirect-calls",
            "-fno-sanitize=fuzzer",
        ],
        linkopts = [
            "-fno-sanitize=fuzzer",
        ],
    ),
    asan = _make_opts(
        copts = ["-fsanitize=address"],
        linkopts = ["-fsanitize=address"],
    ),
    msan = _make_opts(
        copts = ["-fsanitize=memory"],
        linkopts = ["-fsanitize=memory"],
    ),
    msan_origin_tracking = _make_opts(
        copts = [
            "-fsanitize=memory",
            "-fsanitize-memory-track-origins=2",
        ],
        linkopts = ["-fsanitize=memory"],
    ),
)
