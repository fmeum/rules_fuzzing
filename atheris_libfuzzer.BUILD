cc_library(
    name = "atheris_libfuzzer",
    srcs = glob([
        "*.cpp",
    ]),
    hdrs = glob([
        "*.h",
        "*.def",
    ]),
    copts = [
        "-g",
        "-O2",
        "-fno-omit-frame-pointer",
        "-std=c++14",
    ],
    linkstatic = True,
    visibility = ["//visibility:public"],
    alwayslink = True,
)

cc_binary(
    name = "asan_with_fuzzer.so",
    linkshared = True,
    visibility = ["//visibility:public"],
    deps = [
        ":atheris_libfuzzer",
        "@rules_fuzzing_sanitizer_libs//:asan",
    ],
)
