load("@rules_java//java:defs.bzl", "java_library")
load("@batfish//skylark:pmd_test.bzl", "pmd_test")

package(default_visibility = ["//visibility:public"])

java_library(
    name = "frr",
    srcs = glob(
        ["*.java"],
        exclude = ["BUILD"],
    ),
    deps = [
        "//projects/batfish-common-protocol:common",
        "@maven//:com_google_code_findbugs_jsr305",
        "@maven//:com_google_guava_guava",
        "@maven//:org_antlr_antlr4_runtime",
    ],
)

pmd_test(
    name = "pmd",
    lib = ":frr",
)
