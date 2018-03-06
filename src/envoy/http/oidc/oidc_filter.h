#pragma once

#include <string>
#include <mutex>

#include "common/common/logger.h"
#include "envoy/http/filter.h"
#include "envoy/upstream/cluster_manager.h"

#include "src/envoy/utils/jwt_authenticator.h"
#include "src/envoy/utils/session_manager.h"
#include "state_store.h"
#include "src/envoy/http/oidc/config.pb.h"

namespace Envoy {
  namespace Http {
    class OidcFilter
      : public StreamFilter,
        public Utils::JwtAuth::JwtAuthenticator::Callbacks,
        public Http::AsyncClient::Callbacks, Logger::Loggable<Logger::Id::filter> {
      public:
        /* OidcFilter constructor.
         * @param manager the cluster manager to address the configured OIDC provider.
         * @param the name of the configured OIDC provider.
         */
        OidcFilter(
            Upstream::ClusterManager &cluster_manager,
            Utils::SessionManager::SessionManagerPtr session_manager,
            StateStore &state_store,
            Runtime::RandomGenerator &rng,
            Utils::JwtAuth::JwtAuthStore& auth_store,
            const Http::Oidc::Config::OidcConfig &config);
        ~OidcFilter();

        // Http::StreamFilterBase
        void onDestroy() override;

        // Http::StreamDecoderFilter
        /* Entry point for decoding request headers. */
        FilterHeadersStatus decodeHeaders(HeaderMap& headers, bool) override;
        /* Entry point for decoding request data. */
        FilterDataStatus decodeData(Buffer::Instance&, bool) override;
        /* Entry point for decoding request headers. */
        FilterTrailersStatus decodeTrailers(HeaderMap&) override;
        /* Decoder configuration. */
        void setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) override;
        // Http::StreamEncoderFilter
        FilterHeadersStatus encode100ContinueHeaders(HeaderMap&) override {
          return FilterHeadersStatus::Continue;
        };
        FilterHeadersStatus encodeHeaders(HeaderMap& headers, bool end_stream) override;
        FilterDataStatus encodeData(Buffer::Instance&, bool) override {
          return FilterDataStatus::Continue;
        }
        FilterTrailersStatus encodeTrailers(HeaderMap&) override {
          return FilterTrailersStatus::Continue;
        };
        void setEncoderFilterCallbacks(StreamEncoderFilterCallbacks& callbacks) override {
          encoder_callbacks_ = &callbacks;
        }

        // Http::AsyncClient::Callbacks
        /* onSuccess is used to handle oidc token responses verifying the succes of a request
         * as well as token validity.
         * @param response the response to be verified.*/
        void onSuccess(MessagePtr&& response);
        /* onFailure is used to handle oidc token request failures. 
         * @param reason the reason an http request failed*/
        void onFailure(AsyncClient::FailureReason reason);
        
        // Utils::JwtAuthenticator::Callbacks
        /* onDone is used to handle asynchronous JWT verifications
         * @param status the status of the verification.
         * @param jwt the verified JWT.
         */
        void onDone(const Utils::JwtAuth::Status& status, const Utils::JwtAuth::Jwt* jwt);

        /* urlSafeEncode encodes the given parameter so that it can included as a query string in a url.
         * Ideally this function should be moved into utilities.h or replaced completely.
         * @param param the parameter to encode.
         */
        static std::string urlSafeEncode(const std::string &param);

        /* isSupportedContentType verifies whether the given media-type is a supported in a token redemption
         * response.
         * @param got the received media-type.
         * @return true if the media-type is supported.
         */
        static bool isSupportedContentType(const LowerCaseString &got);

        /* makeSetCookieValueHttpOnly encodes the given cookie including the name, value, max-age as well as including
         * the HttpOnly, Secure and Strict tags.
         * @param name the name of the cookie.
         * @param value the value of the cookie.
         * @param max_age the expiry of the cookie.
         * @return the encoded cookie.
         */
        static std::string makeSetCookieValueHttpOnly(const std::string &name, const std::string &value, int64_t max_age);
        /* makeSetCookieValueHttpOnly encodes the given cookie including the name, value, max-age as well as including
         * the Strict and Secure tags.
         * @param name the name of the cookie.
         * @param value the value of the cookie.
         * @param max_age the expiry of the cookie.
         * @return the encoded cookie.
         */
        static std::string makeSetCookieValue(const std::string &name, const std::string &value, int64_t max_age);

      private:
        struct RequestContext {
          AsyncClient::Request *request;
          const Http::Oidc::Config::OidcConfig::IdP *idp;
          std::string nonce;
        };

        enum state {
          init,
          stopped,
          replied,
          forwarding,
          setCookie,
        };

        HeaderMap* headers_ = nullptr;
        state state_machine_ = state::init;
        Upstream::ClusterManager &cluster_manager_;
        std::string cluster_;
        Utils::SessionManager::SessionManagerPtr session_manager_;
        StateStore &state_store_;
        Runtime::RandomGenerator &rng_;
        Utils::JwtAuth::JwtAuthenticator jwt_auth_;
        const Http::Oidc::Config::OidcConfig &config_;
        RequestContext auth_request_;
        std::string jwt_;
        int64_t expiry_;
        StreamDecoderFilterCallbacks* decoder_callbacks_;
        StreamEncoderFilterCallbacks* encoder_callbacks_;

        /* random generates a random, url-safe string for use as a nonce or challenge.
         * @param bits the number of bits of randomness i.e. 256
         * @return a url-safe encoded string
         */
        std::string random(size_t bits);
        /* redeemCode redeems the given code for authorization and ID tokens at the token endpoint/
         * @param idp the idp configuration.
         * @param host the host that the token belongs to.
         * @param nonce to be included in the id_token.
         * @param code the one-time code to redeem.
         */
        void redeemCode(const std::string &idp, const std::string &host, const std::string &nonce, const std::string &code);
        /* handleAuthenticationResponse handles a redirection from an OIDC provider after a user has
         * authenitcated.
         * @param method the HTTP verb the request was made with.
         * @param url the url including query parameters addressed.
         */
        void handleAuthenticationResponse(const std::string &method, const std::string &url);
        /* redirectToAuthenticationServer redirects a user agent to an OIDC provider for authentication.
         * @param idp_name the idp identifier.
         * @param idp the idp to redirect to.
         * @param host the host being addressed that'll be used to forward a token redemption code.
         */
        void redirectToAuthenticationServer(const std::string &idp_name, const Http::Oidc::Config::OidcConfig::IdP &idp, const std::string &host);
        /* verifyToken verifies a JWT token is authentic.
         * @param token the token to verify.
         */
        void verifyIdToken(const std::string &token);
    };
  } // Http
} // Envoy
