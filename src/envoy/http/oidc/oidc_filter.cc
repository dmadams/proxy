#include <chrono>
#include <ctime>
#include <string>


#include "oidc_filter.h"

#include "common/common/hex.h"
#include "common/common/enum_to_int.h"
#include "common/http/codes.h"
#include "common/http/utility.h"
#include "common/http/message_impl.h"

namespace Envoy {
  namespace Http {
    namespace {
      const char hexTable[16] = {
        '0', '1', '2', '3',
        '4', '5', '6', '7',
        '8', '9', 'A', 'B',
        'C', 'D', 'E', 'F'
      };
      const LowerCaseString validTokenResponseContentTypes[] = {
        LowerCaseString{"application/json"},
        LowerCaseString{"application/json; charset=utf-8"},
      };
      const std::chrono::milliseconds tokenRedemptionTimeout(120 * 1000); // 120 seconds
      // TODO: Define the below cookie and token name constants in a shared header for use
      // in the xsrf_filter and here.
      const std::string tokenCookieName = "istio_session";
      const std::string xsrfCookieName = "XSRF-TOKEN";
      const LowerCaseString setCookieHeader("set-cookie");
      const LowerCaseString xsrfHeaderName{"x-xsrf-token"};
      const std::chrono::seconds authentictionResponseTimeout(5*60); // 5 minutes
      const std::string tokenResponseSchema(
          R"EOF(
          {
            "$schema": "http://json-schema.org/schema#",
            "type" : "object",
            "properties" : {
              "access_token": {"type": "string"},
              "id_token": {"type": "string"},
              "token_type": {"type": "string", "enum": ["Bearer"]},
              "expires_in": {"type": "integer"}
            },
            "required" : ["id_token"],
            "additionalProperties" : true
          }
        )EOF"
          );

      typedef std::vector<std::pair<const LowerCaseString &, std::string>> AdditionalHeaders_t;

      /* Give an expiration point in seconds from the unix epoch, calculate how many seconds are left. */
      /* Warning: This will not work on a non-Unix machine. */
      int64_t expiry(int64_t timestamp) {
        std::chrono::seconds now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch());
        std::chrono::seconds expiration = std::chrono::seconds(timestamp) - now;
        return expiration.count();
      }
      void sendResponse(StreamDecoderFilterCallbacks& callbacks,
                        Code response_code,
                        const AdditionalHeaders_t &additionalHeaders) {
        HeaderMapPtr response_headers{
          new HeaderMapImpl{
            {Headers::get().Status, std::to_string(enumToInt(response_code))},
          }
        };
        for(auto iter = additionalHeaders.begin(); iter != additionalHeaders.end(); ++iter) {
          response_headers->addCopy(iter->first, iter->second);
        }
        callbacks.encodeHeaders(std::move(response_headers), true);
      }
      
      void sendRedirect(StreamDecoderFilterCallbacks& callbacks,
                        const std::string& new_path,
                        Code response_code,
                        const AdditionalHeaders_t &additionalHeaders) {
        AdditionalHeaders_t allHeaders = additionalHeaders;
        allHeaders.push_back(std::pair<const LowerCaseString &, std::string>(Headers::get().Location, new_path));
        sendResponse(callbacks, response_code, allHeaders);
      }

      void sendRedirect(StreamDecoderFilterCallbacks& callbacks,
                        const std::string& new_path,
                        Code response_code) {
        AdditionalHeaders_t additionalHeaders;
        sendRedirect(callbacks, new_path, response_code, additionalHeaders); 
      }
    } // unnamed namespace

    std::string OidcFilter::urlSafeEncode(const std::string &param) {
      std::ostringstream result;
      for(auto character = param.begin(); character != param.end(); character++) {
        if(*character ==  ' ') {
          result << "%20";
        } else if((*character >= 'A' && *character <= 'Z') ||
            (*character >= 'a' && *character <= 'z') ||
            (*character >= '0' && *character <= '9') ||
            (*character == '*') ||
            (*character == '-') ||
            (*character == '_') ||
            (*character == '~')) {
          result << *character;
        } else {
          result << '%' << hexTable[((*character & 0xF0) >> 4)] << hexTable[(*character & 0x0F)];
        }
      }
      return result.str();
    }

    bool OidcFilter::isSupportedContentType(const LowerCaseString &got) {
      for(size_t i = 0; i < sizeof(validTokenResponseContentTypes)/sizeof(LowerCaseString); i++) {
        if(got == validTokenResponseContentTypes[i]) {
          return true;
        }
      }
      return false;
    }

    std::string OidcFilter::makeSetCookieValueHttpOnly(const std::string &name, const std::string &value, int64_t max_age) {
      // We use the following cookie attributes for the following reasons:
      // - Max-Age: provides a limited session time frame.
      // - Secure: instruct the user-agent (browser) to only send this cookie over a secure link.
      // - HttpOnly: instruct the user-agent (browser) to disallow access to this cookie from Javascript.
      // - SameSite=strict: instruct the user-agent (browser) to prevent 3rd-party site requests using this cookie.`
      return fmt::format("{}=\"{}\"; Max-Age={}; Secure; HttpOnly; SameSite=strict", name, value, max_age);
    }

    std::string OidcFilter::makeSetCookieValue(const std::string &name, const std::string &value, int64_t max_age) {
      // We use the following cookie attributes for the following reasons:
      // - Max-Age: provides a limited session time frame.
      // - Secure: instruct the user-agent (browser) to only send this cookie over a secure link.
      // - SameSite=strict: instruct the user-agent (browser) to prevent 3rd-party site requests using this cookie.`
      return fmt::format("{}=\"{}\"; Max-Age={}; Secure; SameSite=strict", name, value, max_age);
    }

    std::string OidcFilter::random(size_t bits) {
      // Round bits to bytes
      size_t bytes = (bits + 7) / 8;
      // Round bytes to the number of uint64_t we need to read.
      size_t loops = (bytes+(sizeof(uint64_t)-1))/sizeof(uint64_t);
      std::ostringstream output;
      for(size_t i = 0; i < loops; i++) {
        uint64_t part = rng_.random();
        output << Hex::uint64ToHex(part);
      }
      return output.str();
    }

    OidcFilter::OidcFilter(
        Upstream::ClusterManager &cluster_manager,
        Utils::SessionManager::SessionManagerPtr session_manager,
        StateStore &state_store,
        Runtime::RandomGenerator &rng,
        Utils::JwtAuth::JwtAuthStore& auth_store,
        const Http::Oidc::Config::OidcConfig &config):
      cluster_manager_(cluster_manager),
      session_manager_(session_manager),
      state_store_(state_store),
      rng_(rng),
      jwt_auth_(cluster_manager, auth_store),
      config_(config),
      auth_request_(RequestContext {}),
      decoder_callbacks_(nullptr)
    {
      ENVOY_LOG(trace, "{}", __func__);
    }

    OidcFilter::~OidcFilter() {
      ENVOY_LOG(trace, "{}", __func__);
    }

    void OidcFilter::onDestroy() {
      if (auth_request_.request) {
        auth_request_.request->cancel();
        auth_request_.request = nullptr;
      }
    }

    void OidcFilter::redeemCode(const std::string &idp, const std::string &host, const std::string &nonce, const std::string &code) {
      ENVOY_LOG(trace, "Attempting to redeem code {}, for idp {}", code, idp);
      const auto &matches = config_.matches();
      auto iter = matches.find(idp);
      if(iter == matches.end()) {
        // Not an IdP we know about. This could happen due to eventual consistency when multiple envoy instances are
        // deployed.
        ENVOY_LOG(warn, "Received authentication response with unknown IdP: {}. ", idp);
        Utility::sendLocalReply(*decoder_callbacks_, false, Code::BadRequest, CodeUtility::toString(Code::BadRequest));
        state_machine_ = state::replied;
        return;
      }
      auto idpRef = iter->second.idp();
      MessagePtr request(new RequestMessageImpl());
      request->headers().insertMethod().value(Http::Headers::get().MethodValues.Post);
      request->headers().insertScheme().value(Http::Headers::get().SchemeValues.Https);
      request->headers().insertPath().value(std::string(idpRef.token_endpoint().path()));
      request->headers().insertHost().value(idpRef.token_endpoint().host());
      request->headers().insertContentType().value(std::string("application/x-www-form-urlencoded"));
      std::ostringstream endpoint_stream;
      endpoint_stream << "https://" << host << config_.authentication_callback();

      auto body = "code=" + code
        + "&client_id="
        + idpRef.client_id()
        + "&client_secret="
        + idpRef.client_secret()
        + "&redirect_uri="
        + urlSafeEncode(endpoint_stream.str())
        + "&grant_type=authorization_code";
      ENVOY_LOG(trace, "Redempton body: {}", body);
      request->body().reset(new Buffer::OwnedImpl(body));
      ENVOY_LOG(trace, "Sending async code redemption message ...");
      auth_request_.nonce = nonce;
      auth_request_.idp = &idpRef;
      auth_request_.request = cluster_manager_.httpAsyncClientForCluster(idpRef.token_endpoint().cluster())
        .send(std::move(request), *this, Optional<std::chrono::milliseconds>(tokenRedemptionTimeout));
    }

    void OidcFilter::handleAuthenticationResponse(const std::string &method, const std::string &url) {
      // Verify the authentication callback by:
      // - extract and check the state is valid (this is an expected request.
      // - extract the authorization code and redeem  at the authorization token endpoint.
      if(Headers::get().MethodValues.Get != method) {
        ENVOY_LOG(warn, "Received authentication response with incorrect method. Wanted: Get, received: {}", method);
        Utility::sendLocalReply(*decoder_callbacks_, false, Code::BadRequest, CodeUtility::toString(Code::BadRequest));
        state_machine_ = state::replied;
      } else {
        auto parameters = Utility::parseQueryString(url);
        auto state = parameters.find("state");
        auto code = parameters.find("code");
        if(state == parameters.end() || code == parameters.end()) {
          // This is a badly formed command.
          ENVOY_LOG(info, "Missing state or code parameter in handleAuthenticationResponse");
          Utility::sendLocalReply(*decoder_callbacks_,
              false,
              Code::BadRequest,
              CodeUtility::toString(Code::BadRequest));
          state_machine_ = state::replied;
        } else {
          auto ctx = state_store_.get(state->second);
          if (ctx != state_store_.end()) {
            // State has been found. Redeem JWT using the authorization code.
            ENVOY_LOG(trace, "Valid state in handleAuthenticationResponse. Redeeming token...");
            redeemCode(ctx.idp_, ctx.hostname_, ctx.nonce_, code->second);
          } else {
            // Unknown/unexpected state
            ENVOY_LOG(info, "Invalid state in handleAuthenticationResponse");
            Utility::sendLocalReply(*decoder_callbacks_, false, Code::BadRequest, CodeUtility::toString(Code::BadRequest));
            state_machine_ = state::replied;
          }
        }
      }
    }

    void OidcFilter::redirectToAuthenticationServer(const std::string &idp_name, const Http::Oidc::Config::OidcConfig::IdP &idp, const std::string &host) {
      auto nonce = random(256);
      StateStore::StateContext ctx(idp_name, nonce, host);
      auto state = state_store_.create(ctx, authentictionResponseTimeout);
      // We need to construct our local authentication callback endpoint.
      std::ostringstream endpoint_stream;
      endpoint_stream << "https://" << host << config_.authentication_callback();
      std::ostringstream location_stream;
      location_stream << idp.authentication_endpoint()
        << "?response_type=code&scope=openid%20email&"
        << "client_id=" << idp.client_id()
        << "&state=" << state
        << "&nonce=" << nonce
        << "&redirect_uri=" << urlSafeEncode(endpoint_stream.str());
      sendRedirect(*decoder_callbacks_, location_stream.str(), Http::Code::Found);
    }

    void OidcFilter::verifyIdToken(const std::string &token) {
      ENVOY_LOG(trace, "{}", __func__);
      jwt_auth_.Verify(token, this);
    }

    FilterHeadersStatus OidcFilter::decodeHeaders(HeaderMap& headers, bool) {
      ENVOY_LOG(trace, "{}", __func__);
      headers_ = &headers;
      auto authz = headers.get(Headers::get().Authorization);
      if(authz) {
        // We have an authorization header so we let processing continue.
        ENVOY_LOG(trace, "Request contains authorization header. Passing through as is.");
        state_machine_ = state::forwarding;
        return FilterHeadersStatus::Continue;
      }
      // Check if the request is directed at our local authentication callback endpoint.
      auto host = headers.get(Headers::get().Host);
      auto destination = headers.get(Headers::get().Path);
      auto method = headers.get(Headers::get().Method);

      if(host && destination && method) {
        ENVOY_LOG(trace, "{} decoder headers with host: {}, dest: {}, method: {}", __func__, host->value().c_str(), destination->value().c_str(), method->value().c_str());
        auto destination_str = std::string(destination->value().c_str());
        // Is this for our authentication callback?
        auto position = destination_str.find(config_.authentication_callback()); // TODO: There must be a better way to match urls?
        if(position == 0) {
          handleAuthenticationResponse(method->value().c_str(), destination_str);
          ENVOY_LOG(trace, "{} decoder headers completed with outstanding token redemption", __func__);
          if (state_machine_ == state::replied) {
            return FilterHeadersStatus::StopIteration;
          } else {
            state_machine_ = state::stopped;
            return FilterHeadersStatus::StopIteration;
          }
        } else {
          // Find a Match for the request
          for(const auto &match : config_.matches()) {
            const auto& criteriaRef = match.second.criteria();
            auto header = headers.get(Http::LowerCaseString(criteriaRef.header()));
            if(header && std::string(header->value().c_str()) == criteriaRef.value()) {
              ENVOY_LOG(trace, "{} request matches criteria {}:{}", __func__, criteriaRef.header(), criteriaRef.value());
              redirectToAuthenticationServer(match.first, match.second.idp(), host->value().c_str());
              if (state_machine_ == state::replied) {
                return FilterHeadersStatus::StopIteration;
              } else {
                state_machine_ = state::stopped;
                return FilterHeadersStatus::StopIteration;
              }
            }
          }
          ENVOY_LOG(trace, "{} decoder headers unauthenticated request.", __func__);
          state_machine_ = state::forwarding;
          return FilterHeadersStatus::Continue;
        }
      } else {
        ENVOY_LOG(warn, "Received request without host, path and/or method.");
        Utility::sendLocalReply(*decoder_callbacks_, false, Code::BadRequest, CodeUtility::toString(Code::BadRequest));
        state_machine_ = state::replied;
        return FilterHeadersStatus::StopIteration;
      }
    }

    FilterDataStatus OidcFilter::decodeData(Buffer::Instance&, bool) {
      return FilterDataStatus::Continue;
    }

    FilterTrailersStatus OidcFilter::decodeTrailers(HeaderMap&) {
      return FilterTrailersStatus::Continue;
    }

    FilterHeadersStatus OidcFilter::encodeHeaders(HeaderMap& headers, bool) {
      ENVOY_LOG(trace, "OidcFilter {}", __func__);
      if (state_machine_ == state::setCookie) {
        ENVOY_LOG(trace, "OidcFilter {} setting cookies in reply", __func__);
        int64_t seconds_until_expiration = expiry(expiry_);
        // Expire cookie 30 seconds before the jwt.
        int64_t cookieLifetime = std::max(seconds_until_expiration - 30, int64_t(0));
        auto xsrfToken = session_manager_->createXsrfToken(jwt_);
        auto xsrf = makeSetCookieValue(xsrfCookieName, xsrfToken, cookieLifetime);
        auto cookie = makeSetCookieValueHttpOnly(tokenCookieName, jwt_, cookieLifetime);
        headers.addCopy(setCookieHeader, xsrf);
        headers.addCopy(setCookieHeader, cookie);
      }
      return FilterHeadersStatus::Continue;
    }

    void OidcFilter::setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) {
      ENVOY_LOG(trace, "OidcFilter {}", __func__);
      decoder_callbacks_ = &callbacks;
    }

    void OidcFilter::onSuccess(MessagePtr&& response) {
      auth_request_.request = nullptr;
      uint64_t response_code = Utility::getResponseStatus(response->headers());
      std::string response_body(response->bodyAsString());
      ENVOY_LOG(debug, "Received response from token endpoint: {}", response_code);
      if (response_code != enumToInt(Http::Code::OK)) {
        Utility::sendLocalReply(*decoder_callbacks_, false, Code::Unauthorized, CodeUtility::toString(Code::Unauthorized));
        state_machine_ = state::replied;
      } else {
        // Verify content-type of response is application/json
        auto content_type = response->headers().get(Headers::get().ContentType);
        if(!content_type || !isSupportedContentType(LowerCaseString(content_type->value().c_str(), true))) {
          ENVOY_LOG(info, "Unexpected or missing Content-type in token response.");
          if(content_type) {
            ENVOY_LOG(info, "Got Content-type {}", content_type->value().c_str());
          }
          Utility::sendLocalReply(*decoder_callbacks_, false, Code::BadGateway, CodeUtility::toString(Code::BadGateway));
          state_machine_ = state::replied;
        } else {
          Json::ObjectSharedPtr token_response = Json::Factory::loadFromString(response->bodyAsString());
          // Verify response body conforms to that defined in http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
          token_response->validateSchema(tokenResponseSchema);
          // Extract identity token.
          auto id_token = token_response->getString("id_token");
          // asynchronous verification of token
          verifyIdToken(id_token);
        }
      }
    }

    void OidcFilter::onFailure(AsyncClient::FailureReason) {
      auth_request_.request = nullptr;
      ENVOY_LOG(warn, "Token endpoint request reset.");
      Utility::sendLocalReply(*decoder_callbacks_, false, Code::InternalServerError, CodeUtility::toString(Code::InternalServerError));
      state_machine_ = state::replied;
    }
    
    void OidcFilter::onDone(const Utils::JwtAuth::Status& status, const Utils::JwtAuth::Jwt* jwt) {
      if (state_machine_ == state::replied) {
        return;
      }
      ENVOY_LOG(trace, "{} state: {}", __func__, int(status));
      if (status != Utils::JwtAuth::Status::OK) {
        // verification failed
        ENVOY_LOG(info, "{} id_token verification failed: {}", __func__, int(status));
        Utility::sendLocalReply(*decoder_callbacks_, false, Code::Unauthorized, CodeUtility::toString(Code::Unauthorized));
        state_machine_ = state::replied;
      } else {
        auto nonce = jwt->Payload()->getString("nonce", "");
        if(auth_request_.nonce != nonce) {
          ENVOY_LOG(debug,
              "{} Authentication failed as the expected nonce claim is missing or incorrect. nonce: {}, expected: {}.", __func__,
              nonce,
              auth_request_.nonce);;
          Utility::sendLocalReply(*decoder_callbacks_, false, Code::Unauthorized, CodeUtility::toString(Code::Unauthorized));
          state_machine_ = state::replied;
        } else {
          jwt_ = jwt->Str();
          expiry_ = jwt->Exp();
          ENVOY_LOG(debug, "{} Authentication complete, redirecting to landing page.", __func__);
          // Rewrite request and forward to landing page including JWT.
          std::string bearerTokenValue = "Bearer " +  jwt_;
          headers_->addCopy(Headers::get().Authorization, bearerTokenValue);
          headers_->remove(Headers::get().Path);
          headers_->addCopy(Headers::get().Path, config_.landing_page());
          if (state_machine_ == state::stopped) {
            decoder_callbacks_->continueDecoding();
          }
          state_machine_ = state::setCookie;
        }
      }
    }
  } // Http
} // Envoy
