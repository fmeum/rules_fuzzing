load("@pybind11_bazel//:build_defs.bzl", "pybind_extension", "pybind_library")
load("@rules_fuzzing//fuzzing/private:binary.bzl", "uninstrumented_cc_library")

pybind_library(
    name = "atheris_lib_original_",
    srcs = [
        "fuzzed_data_provider.cc",
        "libfuzzer.cc",
        "tracer.cc",
        "util.cc",
    ],
    hdrs = [
        "atheris.h",
        "fuzzed_data_provider.h",
        "macros.h",
        "tracer.h",
        "util.h",
    ],
)

uninstrumented_cc_library(
    name = "atheris_lib",
    library = ":atheris_lib_original_",
)

pybind_extension(
    name = "atheris_no_libfuzzer",
    srcs = [
        "atheris.cc",
    ],
    local_defines = [
        "ATHERIS_MODULE_NAME=atheris_no_libfuzzer",
    ],
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
