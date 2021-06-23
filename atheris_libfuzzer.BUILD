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
        "-std=c++11",
    ],
    visibility = ["//visibility:public"],
    alwayslink = True,
)

cc_binary(
    name = "asan_with_fuzzer.so",
    linkopts = [
        "-fsanitize=address",
        "-rdynamic",
    ],
    linkshared = True,
    visibility = ["//visibility:public"],
    deps = [
        ":atheris_libfuzzer",
    ],
)

cc_binary(
    name = "ubsan_with_fuzzer.so",
    linkopts = [
        "-fsanitize=undefined",
        "-rdynamic",
    ],
    linkshared = True,
    visibility = ["//visibility:public"],
    deps = [
        ":atheris_libfuzzer",
    ],
)
