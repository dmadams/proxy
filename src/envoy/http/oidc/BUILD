package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_cc_mock",
)

load(
    "@envoy_api//bazel:api_build_system.bzl",
    "api_proto_library",
)

api_proto_library(
    name = "config_proto",
    srcs = [":config.proto"],
    deps = [
        "//src/envoy/utils:config_proto",
    ],
    visibility = ["//visibility:public"],
    require_py = 0,
)

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        ":oidc_filter_config",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)

envoy_cc_library(
    name = "oidc_filter_lib",
    srcs = ["oidc_filter.cc", "state_store.cc"],
    hdrs = ["oidc_filter.h", "state_store.h"],
    repository = "@envoy",
    deps = [
        ":config_proto_cc",
        "//src/envoy/utils:session_manager_lib",
        "//src/envoy/utils:jwt_authenticator_lib",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_library(
    name = "oidc_filter_config",
    srcs = ["oidc_filter_config.cc"],
    repository = "@envoy",
    deps = [
        ":config_proto_cc",
        ":oidc_filter_lib",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_mock(
    name = "mocks",
    srcs = ["mocks.cc"],
    repository = "@envoy",
    hdrs = ["mocks.h"],
    deps = [
        ":oidc_filter_lib"
    ]
)

envoy_cc_test(
    name = "oidc_filter_test",
    srcs = ["oidc_filter_test.cc"],
    repository = "@envoy",
    deps = [
        ":oidc_filter_lib",
        ":mocks",
        "//src/envoy/utils:mocks",
        "@envoy//test/integration:http_integration_lib",
    ],
)
