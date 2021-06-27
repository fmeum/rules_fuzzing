load("@rules_foreign_cc//foreign_cc:defs.bzl", "configure_make")
load("@bazel_skylib//rules:select_file.bzl", "select_file")
load("@bazel_skylib//rules:copy_file.bzl", "copy_file")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

configure_make(
    name = "python3",
    configure_options = [
        "CFLAGS='-Dredacted=\"redacted\"'",
        "--with-openssl=$EXT_BUILD_DEPS/openssl",
        "--with-zlib=$EXT_BUILD_DEPS/zlib",
        "--enable-optimizations",
    ],
    env = select({
        "@platforms//os:macos": {"AR": ""},
        "//conditions:default": {},
    }),
    features = select({
        "@platforms//os:macos": ["-headerpad"],
        "//conditions:default": {},
    }),
    # rules_foreign_cc defaults the install_prefix to "python". This conflicts with the "python" executable that is generated.
    install_prefix = "py_install",
    lib_source = ":all_srcs",
    out_binaries = [
        "python3.9",
    ],
    out_data_dirs = ["lib"],
    deps = [
        "@openssl",
        "@zlib",
    ],
)

filegroup(
    name = "python3_bin",
    srcs = [":python3"],
    output_group = "python3.9",
)

select_file(
    name = "python3_interpreter_",
    srcs = ":python3",
    subpath = "python3.9",
)

copy_file(
    name = "python3_interpreter",
    src = ":python3_interpreter_",
    out = "python3.9",
    is_executable = True,
)


