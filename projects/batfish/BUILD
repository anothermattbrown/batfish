load("@rules_java//java:defs.bzl", "java_library")
load("@batfish//skylark:junit.bzl", "junit_tests")
load("@batfish//skylark:pmd_test.bzl", "pmd_test")

package(default_visibility = ["//visibility:public"])

java_library(
    name = "batfish",
    srcs = glob([
        "src/main/**/*.java",
    ]),
    plugins = [
        "//:auto_service_plugin",
    ],
    resources = [
        "src/main/resources/org/batfish/config/batfish.properties",
        "src/main/resources/org/batfish/representation/aws/ip-ranges.json",
    ],
    runtime_deps = [
        "//projects/question",
        "@maven//:org_apache_logging_log4j_log4j_slf4j_impl",
    ],
    deps = [
        "//projects/batfish-common-protocol:common",
        "//projects/batfish/src/main/antlr4/org/batfish/grammar/flatvyos",
        "//projects/batfish/src/main/antlr4/org/batfish/grammar/mrv",
        "//projects/batfish/src/main/antlr4/org/batfish/grammar/routing_table/eos",
        "//projects/batfish/src/main/antlr4/org/batfish/grammar/routing_table/ios",
        "//projects/batfish/src/main/antlr4/org/batfish/grammar/routing_table/nxos",
        "//projects/batfish/src/main/antlr4/org/batfish/grammar/vyos",
        "//projects/batfish/src/main/java/org/batfish/grammar/arista",
        "//projects/batfish/src/main/java/org/batfish/grammar/cisco",
        "//projects/batfish/src/main/java/org/batfish/grammar/cisco_asa",
        "//projects/batfish/src/main/java/org/batfish/grammar/cisco_nxos",
        "//projects/batfish/src/main/java/org/batfish/grammar/cisco_xr",
        "//projects/batfish/src/main/java/org/batfish/grammar/cumulus_concatenated",
        "//projects/batfish/src/main/java/org/batfish/grammar/cumulus_nclu",
        "//projects/batfish/src/main/java/org/batfish/grammar/f5_bigip_structured",
        "//projects/batfish/src/main/java/org/batfish/grammar/flatjuniper",
        "//projects/batfish/src/main/java/org/batfish/grammar/fortios",
        "//projects/batfish/src/main/java/org/batfish/grammar/frr",
        "//projects/batfish/src/main/java/org/batfish/grammar/iptables",
        "//projects/batfish/src/main/java/org/batfish/grammar/juniper",
        "//projects/batfish/src/main/java/org/batfish/grammar/palo_alto",
        "//projects/batfish/src/main/java/org/batfish/grammar/palo_alto_nested",
        "//projects/batfish/src/main/java/org/batfish/representation/aws",
        "//projects/batfish/src/main/java/org/batfish/representation/host",
        "//projects/batfish/src/main/java/org/batfish/representation/iptables",
        "//projects/batfish/src/main/java/org/batfish/vendor/a10/grammar",
        "//projects/batfish/src/main/java/org/batfish/vendor/check_point_gateway/grammar",
        "//projects/batfish/src/main/java/org/batfish/vendor/check_point_management",
        "//projects/batfish/src/main/java/org/batfish/vendor/check_point_management/parsing",
        "//projects/batfish/src/main/java/org/batfish/vendor/sonic/grammar",
        "//projects/bdd",
        "//projects/symbolic",
        "@maven//:com_fasterxml_jackson_core_jackson_annotations",
        "@maven//:com_fasterxml_jackson_core_jackson_core",
        "@maven//:com_fasterxml_jackson_core_jackson_databind",
        "@maven//:com_github_ben_manes_caffeine_caffeine",
        "@maven//:com_google_auto_service_auto_service_annotations",
        "@maven//:com_google_code_findbugs_jsr305",
        "@maven//:com_google_errorprone_error_prone_annotations",
        "@maven//:com_google_guava_guava",
        "@maven//:com_ibm_icu_icu4j",
        "@maven//:commons_io_commons_io",
        "@maven//:jakarta_ws_rs_jakarta_ws_rs_api",
        "@maven//:org_antlr_antlr4_runtime",
        "@maven//:org_apache_commons_commons_collections4",
        "@maven//:org_apache_commons_commons_configuration2",
        "@maven//:org_apache_commons_commons_lang3",
        "@maven//:org_apache_logging_log4j_log4j_api",
        "@maven//:org_codehaus_jettison_jettison",
        "@maven//:org_glassfish_grizzly_grizzly_http_server",
        "@maven//:org_glassfish_jersey_containers_jersey_container_grizzly2_http",
        "@maven//:org_glassfish_jersey_core_jersey_server",
        "@maven//:org_glassfish_jersey_media_jersey_media_json_jettison",
        "@maven//:org_jgrapht_jgrapht_core",
    ],
)

java_library(
    name = "batfish_testlib",
    testonly = True,
    srcs = glob(
        [
            "src/test/**/*.java",
        ],
        exclude = ["src/test/**/*Test.java"],
    ),
    deps = [
        ":batfish",
        "//projects/batfish-common-protocol:common",
        "//projects/bdd",
        "//projects/symbolic",
        "@maven//:com_google_code_findbugs_jsr305",
        "@maven//:com_google_guava_guava",
        "@maven//:junit_junit",
        "@maven//:org_apache_commons_commons_collections4",
        "@maven//:org_hamcrest_hamcrest",
    ],
)

junit_tests(
    name = "batfish_tests",
    size = "medium",
    srcs = glob([
        "src/test/**/*Test.java",
    ]),
    resources = [
        "//projects/batfish/src/test/resources",
    ],
    tags = ["cpu:4"],
    deps = [
        ":batfish",
        ":batfish_testlib",
        "//projects/batfish-common-protocol:common",
        "//projects/batfish-common-protocol:common_testlib",
        "//projects/batfish-common-protocol/src/test/java/org/batfish/common/matchers",
        "//projects/batfish-common-protocol/src/test/java/org/batfish/datamodel/matchers",
        "//projects/batfish-common-protocol/src/test/java/org/batfish/datamodel/questions:TestQuestion",
        "//projects/batfish-common-protocol/src/test/java/org/batfish/identifiers",
        "//projects/symbolic",
        "@maven//:com_google_code_findbugs_jsr305",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_guava_guava_testlib",
        "@maven//:commons_io_commons_io",
        "@maven//:junit_junit",
        "@maven//:org_hamcrest_hamcrest",
    ],
)

pmd_test(
    name = "pmd",
    lib = ":batfish",
)

pmd_test(
    name = "testlib_pmd",
    lib = ":batfish",
)
