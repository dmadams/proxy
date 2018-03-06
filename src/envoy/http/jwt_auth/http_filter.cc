/* Copyright 2017 Istio Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "src/envoy/http/jwt_auth/http_filter.h"
#include "src/envoy/utils/constants.h"

#include "common/http/message_impl.h"
#include "common/http/utility.h"
#include "envoy/http/async_client.h"
#include "server/config/network/http_connection_manager.h"

#include <chrono>
#include <string>

namespace Envoy {
namespace Http {

JwtVerificationFilter::JwtVerificationFilter(Upstream::ClusterManager& cm,
    Utils::JwtAuth::JwtAuthStore& store,
    const google::protobuf::RepeatedPtrField<Envoy::Utils::Config::HttpPattern> &bypass_jwt)
    : jwt_auth_(cm, store), bypass_jwt_(bypass_jwt){}

JwtVerificationFilter::~JwtVerificationFilter() {}

void JwtVerificationFilter::onDestroy() {
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {}", __func__);
  jwt_auth_.onDestroy();
}

FilterHeadersStatus JwtVerificationFilter::decodeHeaders(HeaderMap& headers,
                                                         bool) {
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {}", __func__);
  headers_ = &headers;
  state_ = Calling;
  stopped_ = false;

  // Check if the request being made does not require Auth.
  if (OkToBypass()) {
    ENVOY_LOG(error, "{} Bypassing authentication check for {} {}",
        __func__,
        headers_->Method()->value().c_str(),
        headers_->Path()->value().c_str());
    return FilterHeadersStatus::Continue;
  }
  // Verify the JWT token, onDone() will be called when completed.
  jwt_auth_.Verify(headers, this);

  if (state_ == Complete) {
    return FilterHeadersStatus::Continue;
  }
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {} Stop", __func__);
  stopped_ = true;
  return FilterHeadersStatus::StopIteration;
}

bool JwtVerificationFilter::OkToBypass() const {
  for (const auto& bypass : bypass_jwt_) {
    if (headers_->Method() && headers_->Path() &&
        // Http method should always match
        bypass.http_method() == headers_->Method()->value().c_str()) {
      if (!bypass.path_exact().empty() &&
          bypass.path_exact() == headers_->Path()->value().c_str()) {
        return true;
      }
      if (!bypass.path_prefix().empty() &&
          StringUtil::startsWith(headers_->Path()->value().c_str(),
                                 bypass.path_prefix())) {
        return true;
      }
    }
  }
  return false;
}

void JwtVerificationFilter::onDone(const Utils::JwtAuth::Status& status, const Utils::JwtAuth::Jwt* jwt) {
  ENVOY_LOG(debug, "Called JwtVerificationFilter : check complete {}",
            int(status));
  // This stream has been reset, abort the callback.
  if (state_ == Responded) {
    return;
  }
  if (status != Utils::JwtAuth::Status::OK) {
    state_ = Responded;
    // verification failed
    Code code = Code(401);  // Unauthorized
    // return failure reason as message body
    Utility::sendLocalReply(*decoder_callbacks_, false, code,
                            Utils::JwtAuth::StatusToString(status));
    return;
  }

  // Add verified header, removed to be processed header.
  headers_->addReferenceKey(Utils::Constants::JwtPayloadKey(), jwt->PayloadStrBase64Url());
  // Why remove the Authorization header? Yes it's been validated but other downstream processes may
  // with to use it later
  //headers_->removeAuthorization();
  state_ = Complete;
  if (stopped_) {
    decoder_callbacks_->continueDecoding();
  }
}

FilterDataStatus JwtVerificationFilter::decodeData(Buffer::Instance&, bool) {
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {}", __func__);
  if (state_ == Calling) {
    return FilterDataStatus::StopIterationAndBuffer;
  }
  return FilterDataStatus::Continue;
}

FilterTrailersStatus JwtVerificationFilter::decodeTrailers(HeaderMap&) {
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {}", __func__);
  if (state_ == Calling) {
    return FilterTrailersStatus::StopIteration;
  }
  return FilterTrailersStatus::Continue;
}

void JwtVerificationFilter::setDecoderFilterCallbacks(
    StreamDecoderFilterCallbacks& callbacks) {
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {}", __func__);
  decoder_callbacks_ = &callbacks;
}

}  // Http
}  // Envoy
