load("@pybind11_bazel//:build_defs.bzl", "pybind_extension")

filegroup(
    name = "atheris_srcs",
    srcs =[
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
)

pybind_extension(
    name = "atheris",
    srcs = [
        ":atheris_srcs",
    ],
    deps = [
        "@atheris_libfuzzer//:fuzzer_no_main",
    ],
)

pybind_extension(
    name = "atheris_no_libfuzzer",
    local_defines = [
        "ATHERIS_MODULE_NAME=atheris_no_libfuzzer",
    ],
    srcs = [
        ":atheris_srcs",
    ],
)

py_library(
    name = "atheris",
    data = [":atheris.so"],
    visibility = ["//visibility:public"],
)

py_library(
    name = "atheris_no_libfuzzer",
    data = [":atheris_no_libfuzzer.so"],
    visibility = ["//visibility:public"],
)
