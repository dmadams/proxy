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

#pragma once

#include "src/envoy/utils/jwt_authenticator.h"

#include "common/common/logger.h"
#include "server/config/network/http_connection_manager.h"

namespace Envoy {
namespace Http {

// The Envoy filter to process JWT auth.
class JwtVerificationFilter : public StreamDecoderFilter,
                              public Utils::JwtAuth::JwtAuthenticator::Callbacks,
                              public Logger::Loggable<Logger::Id::filter> {
 public:
  JwtVerificationFilter(Upstream::ClusterManager& cm,
                        Utils::JwtAuth::JwtAuthStore& store,
                        const google::protobuf::RepeatedPtrField<Envoy::Utils::Config::HttpPattern> &bypass_jwt); 
  ~JwtVerificationFilter();

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  FilterHeadersStatus decodeHeaders(HeaderMap& headers, bool) override;
  FilterDataStatus decodeData(Buffer::Instance&, bool) override;
  FilterTrailersStatus decodeTrailers(HeaderMap&) override;
  void setDecoderFilterCallbacks(
      StreamDecoderFilterCallbacks& callbacks) override;

 private:
  // A function that determines whether the given request can bypass
  // auth.
  bool OkToBypass() const;
  
  // the function for JwtAuth::Authenticator::Callbacks interface.
  // To be called when its Verify() call is completed.
  void onDone(const Utils::JwtAuth::Status& status, const Utils::JwtAuth::Jwt* jwt);

  // The callback funcion.
  StreamDecoderFilterCallbacks* decoder_callbacks_;
  // The auth object.
  Utils::JwtAuth::JwtAuthenticator jwt_auth_;
  // The white-list of endpoints that can bypass the auth filter.
  const google::protobuf::RepeatedPtrField<Envoy::Utils::Config::HttpPattern> &bypass_jwt_;
  // Reference to headers being processed. 
  HeaderMap* headers_;
  // The state of the request
  enum State { Init, Calling, Responded, Complete };
  State state_ = Init;
  // Mark if request has been stopped.
  bool stopped_ = false;
};

}  // Http
}  // Envoy
