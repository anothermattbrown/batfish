load("@batfish//skylark:junit.bzl", "junit_tests")

package(
    default_testonly = True,
    default_visibility = ["//visibility:public"],
)

junit_tests(
    name = "tests",
    srcs = glob([
        "**/*Test.java",
    ]),
    deps = [
        "//projects/batfish-common-protocol:common",
        "//projects/batfish-common-protocol:common_testlib",
        "//projects/batfish/src/main/antlr4/org/batfish/grammar/cumulus_ports",
        "//projects/batfish/src/main/java/org/batfish/grammar/cumulus_ports",
        "//projects/batfish/src/main/java/org/batfish/representation/cumulus_concatenated",
        "//projects/batfish/src/main/java/org/batfish/representation/frr",
        "@maven//:com_google_guava_guava",
        "@maven//:junit_junit",
        "@maven//:org_apache_commons_commons_lang3",
        "@maven//:org_hamcrest_hamcrest",
    ],
)
