load("@pybind11_bazel//:build_defs.bzl", "pybind_extension", "pybind_library")

pybind_library(
    name = "atheris",
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
)

pybind_extension(
    name = "atheris_no_link",
    deps = [
        ":atheris",
    ]
)

pybind_extension(
    name = "atheris",
    deps = [
        ":atheris",
        "@atheris_libfuzzer",
    ],
)
