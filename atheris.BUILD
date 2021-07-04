load("@pybind11_bazel//:build_defs.bzl", "pybind_extension", "pybind_library")
load("@rules_fuzzing//fuzzing/private:binary.bzl", "cc_wrapper_no_instrumentation")

pybind_library(
    name = "atheris_lib_original_",
    srcs = [
        "atheris.cc",
        "atheris.h",
        "fuzzed_data_provider.cc",
        "fuzzed_data_provider.h",
        "libfuzzer.cc",
        "macros.h",
        "tracer.cc",
        "tracer.h",
        "util.cc",
        "util.h",
    ],
    linkstatic = True,
    local_defines = [
        "ATHERIS_MODULE_NAME=atheris_no_libfuzzer",
    ],
    alwayslink = True,
)

cc_wrapper_no_instrumentation(
    name = "atheris_lib",
    original = ":atheris_lib_original_",
)

pybind_extension(
    name = "atheris_no_libfuzzer",
    deps = [
        ":atheris_lib",
    ],
)

py_library(
    name = "atheris_no_libfuzzer",
    data = [
        ":atheris_no_libfuzzer.so",
    ],
    imports = ["."],
    visibility = ["//visibility:public"],
)
