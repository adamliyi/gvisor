load("//tools:defs.bzl", "bzl_library", "go_test")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

go_test(
    name = "packetimpact_test",
    srcs = ["packetimpact_test.go"],
    tags = [
        # Not intended to be run directly.
        "local",
        "manual",
    ],
    deps = [
        "//pkg/test/dockerutil",
        "//test/packetimpact/netdevs",
        "@com_github_docker_docker//api/types/mount:go_default_library",
    ],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
)
