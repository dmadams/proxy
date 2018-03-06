package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
)

envoy_cc_library(
    name = "xsrf_filter_config",
    srcs = ["xsrf_filter_config.cc"],
    repository = "@envoy",
    deps = [
        "//src/envoy/utils:config_proto_cc",
        ":xsrf_filter_lib",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_library(
    name = "xsrf_filter_lib",
    srcs = ["xsrf_filter.cc"],
    hdrs = ["xsrf_filter.h"],
    repository = "@envoy",
    deps = [
        "//src/envoy/utils:session_manager_lib",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_test(
    name = "xsrf_filter_test",
    srcs = ["xsrf_filter_test.cc"],
    repository = "@envoy",
    deps = [
        ":xsrf_filter_lib",
        "//src/envoy/utils:mocks",
        "@envoy//test/integration:http_integration_lib",
    ],
)
