cc_library(
    name = "fuzzer_no_main",
    srcs = glob(
        ["*.cpp"],
        exclude = ["FuzzerMain.cpp"],
    ),
    hdrs = glob([
        "*.h",
        "*.def",
    ]),
    copts = [
        "-std=c++11",
        "-O2",
        "-fPIC",
    ],
    linkopts = [
        "-ldl",
        "-lpthread",
    ],
    linkstatic = True,
    alwayslink = True,
)

cc_binary(
    name = "fuzzer_only.so",
    linkshared = True,
    visibility = ["//visibility:public"],
    deps = [
        ":fuzzer_no_main",
    ],
)

cc_binary(
    name = "asan_with_fuzzer.so",
    linkshared = True,
    visibility = ["//visibility:public"],
    deps = [
        ":fuzzer_no_main",
        "@rules_fuzzing_sanitizer_libs//:asan",
    ],
)
