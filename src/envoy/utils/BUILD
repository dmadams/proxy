# Copyright 2016 Istio Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
#
package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_cc_test",
    "envoy_cc_mock",
)

load(
    "@envoy_api//bazel:api_build_system.bzl",
    "api_proto_library",
)

envoy_cc_library(
    name = "utils_lib",
    srcs = [
        "config.cc",
        "constants.cc",
        "grpc_transport.cc",
        "mixer_control.cc",
        "stats.cc",
        "utils.cc",
    ],
    hdrs = [
        "config.h",
        "constants.h",
        "grpc_transport.h",
        "mixer_control.h",
        "stats.h",
        "utils.h",
    ],
    repository = "@envoy",
    deps = [
        "//src/istio/mixerclient:mixerclient_lib",
        "//external:mixer_client_config_cc_proto",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_test(
    name = "utils_test",
    srcs = [
        "utils_test.cc",
    ],
    deps = [
        ":utils_lib",
        "@envoy//test/test_common:utility_lib",
    ],
    repository = "@envoy",
)

api_proto_library(
    name = "config_proto",
    srcs = [":config.proto"],
    visibility = ["//visibility:public"],
    require_py = 0,
)

envoy_cc_library(
    name = "jwt_lib",
    srcs = ["jwt.cc"],
    hdrs = ["jwt.h"],
    repository = "@envoy",
    deps = [
        "//external:rapidjson",
        "//external:ssl",
        "@envoy//source/exe:envoy_common_lib",
    ],
    visibility = ["//visibility:public"],
)

envoy_cc_library(
    name = "jwt_authenticator_lib",
    srcs = [
        "jwt_authenticator.cc",
    ],
    hdrs = [
        "auth_store.h",
        "jwt_authenticator.h",
        "pubkey_cache.h",
    ],
    repository = "@envoy",
    deps = [
        ":config_proto_cc",
        ":jwt_lib",
        "@envoy//source/exe:envoy_common_lib",
    ],
    visibility = ["//visibility:public"],
)

envoy_cc_test(
    name = "jwt_test",
    srcs = [
        ":jwt_test.cc",
    ],
    data = [],
    repository = "@envoy",
    deps = [
        ":jwt_lib",
        "@envoy//source/exe:envoy_common_lib",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_test(
    name = "jwt_authenticator_test",
    srcs = [
        ":jwt_authenticator_test.cc",
    ],
    data = [],
    repository = "@envoy",
    deps = [
        ":jwt_authenticator_lib",
        "@envoy//source/exe:envoy_common_lib",
        "@envoy//test/mocks/upstream:upstream_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)

envoy_cc_library(
    name = "session_manager_lib",
    srcs = ["session_manager.cc"],
    hdrs = ["session_manager.h"],
    repository = "@envoy",
    deps = [
        ":config_proto_cc",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_mock(
    name = "mocks",
    srcs = ["mocks.cc"],
    repository = "@envoy",
    hdrs = ["mocks.h"],
    deps = [
        ":session_manager_lib"
    ]
)

envoy_cc_test(
    name = "session_manager_test",
    srcs = [
        "session_manager_test.cc",
    ],
    data = [],
    repository = "@envoy",
    deps = [
        ":session_manager_lib",
        "@envoy//source/exe:envoy_common_lib",
        "@envoy//test/mocks/upstream:upstream_mocks",
        "@envoy//test/test_common:utility_lib",
    ],
)
