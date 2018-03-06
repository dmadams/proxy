#include "oidc_filter.h"
#include "src/envoy/utils/config.pb.h"

#include "common/grpc/common.h"
#include "common/http/headers.h"
#include "common/http/utility.h"
#include "common/buffer/buffer_impl.h"

#include "mocks.h"
#include "src/envoy/utils/mocks.h"
#include "test/test_common/utility.h"
#include "test/integration/utility.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/runtime/mocks.h"
#include "test/mocks/upstream/mocks.h"

#include "gmock/gmock.h"

namespace Envoy {
  class HttpFilterOidcTest : public testing::Test {

    public:
      // TODO: Fix this mess!
      /*HttpFilterOidcTest()  {
        session_manager_.reset(new NiceMock<Http::MockSessionManager>());
        filter_.reset(new Http::OidcFilter(cluster_manager_,
              session_manager_,
              state_store_,
              rng_,
              auth_store_,
              config()));
        filter_->setDecoderFilterCallbacks(callbacks_);
      }


      static const Http::Oidc::Config::OidcConfig config(){
        Http::Oidc::Config::OidcConfig config;
        config.authentication_endpoint = "www.some-idp.com";
        config.token_endpoint.cluster = "idp";
        config.token_endpoint.host = "www.some-idp.com";
        config.token_endpoint.path = "/oauth2/token";
        config.authentication_endpoint = "https://some-idp/oauth";
        config.client_id = "0123456789";
        config.client_secret = "Shoo000sh!";
        config.local_authentication_callback = "/oauth";
        config.landing_page = "https://www.somewhere.com/landing.html";
        struct Config
        {
          struct Endpoint{
            std::string cluster;
            std::string host;
            std::string path;
          } token_endpoint;
          std::string authentication_endpoint;
          std::string client_id;
          std::string client_secret;
          std::string local_authentication_callback;
          std::string landing_page;
        };
        return config;
      }
      
      NiceMock<Upstream::MockClusterManager> cluster_manager_;
      Http::SessionManager::SessionManagerPtr session_manager_;
      NiceMock<Http::MockStateStore> state_store_;
      NiceMock<Runtime::MockRandomGenerator> rng_;
      Envoy::Http::Utils::JwtAuthStore auth_store_;
      NiceMock<Http::MockStreamDecoderFilterCallbacks> callbacks_;
      std::unique_ptr<Http::OidcFilter> filter_;
      */
  };


  TEST_F(HttpFilterOidcTest, TestNoOp) {
    // TODO: Remove this NoOp test
    EXPECT_TRUE(true);
  }
 
  // TODO: reinstate the below
  /*
  TEST_F(HttpFilterOidcTest, TestUrlSafeEncode) {
    struct scenario {
      const std::string test;
      const std::string expected;
    } scenarios[]{
      {"http://hello~-_*", "http%3A%2F%2Fhello~-_*"},
      {"https://hello:443/more space", "https%3A%2F%2Fhello%3A443%2Fmore%20space"},
    };

    for(size_t i = 0; i < sizeof(scenarios)/sizeof(scenario); ++i){
      std::string result = Http::OidcFilter::urlSafeEncode(scenarios[i].test);
      EXPECT_EQ(scenarios[i].expected, result);
    }
  }

  TEST_F(HttpFilterOidcTest, TestValidContentTypes) {
    struct scenario {
      const std::string test;
      const bool expected;
    } scenarios[]{
      {"application/json", true},
      {"application/json; charset=utf-8", true},
      {"application/xml", false},
      {"application/xml; charset=utf-8", false},
      {"html", false}
    };

    for(size_t i = 0; i < sizeof(scenarios)/sizeof(scenario); ++i){
      EXPECT_EQ(scenarios[i].expected, Http::OidcFilter::isSupportedContentType(Http::LowerCaseString(scenarios[i].test)));
    }
  }
  
  TEST_F(HttpFilterOidcTest, TestDecodeData) {
    Buffer::OwnedImpl data;
    EXPECT_EQ(Http::FilterDataStatus::Continue, filter_->decodeData(data, true));
    EXPECT_EQ(Http::FilterDataStatus::Continue, filter_->decodeData(data, false));
  }
  
  TEST_F(HttpFilterOidcTest, TestDecodeTrailers) {
    Http::TestHeaderMapImpl headers;
    EXPECT_EQ(Http::FilterTrailersStatus::Continue, filter_->decodeTrailers(headers));
  }

  TEST_F(HttpFilterOidcTest, TestDecodeHeadersAuthZHeaderPresent) {
    // Verify that requests that contain an authorization header bypass the oidc filter.
    Http::TestHeaderMapImpl headers{{":method", "GET"}, {":path", "/"}, {":authority", "host"}, {"authorization", "anything"}};
    EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers, true));
  }
  
  TEST_F(HttpFilterOidcTest, TestDecodeHeadersXsrfCookiePresent) {
    // Verify that requests that contain valid cookies bypass the oidc filter.
    Http::TestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"cookie", "oidc_filter=12345"},
      {"X-XSRF-TOKEN", "abcdef"}
    };
    ON_CALL(session_manager_, verifyToken("12345", "abcdef")).WillByDefault(testing::Return(true));
    EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers, true));
    auto authz = headers.get_(Http::Headers::get().Authorization);
    EXPECT_STREQ("12345", authz.c_str());
  }
  
  TEST_F(HttpFilterOidcTest, TestDecodeHeadersFailsWhenRequestIsBad) {
    // Verify requests fails when:
    // - There's a JWT cookie but no x-xsrf-token header.
    // - There's a JWT cookie and a x-xsrf-token header but they do not match.
    Http::TestHeaderMapImpl scenarios[] = {
      {{":method", "GET"}, {":path", "/"}, {":authority", "host"}, {"host", "host"}, {"cookie", "oidc_filter=session"}},
      {{":method", "GET"}, {":path", "/"}, {":authority", "host"}, {"host", "host"}, {"cookie", "oidc_filter=session"}, {"x-xsrf-token", "invalid"}}
    };
    ON_CALL(session_manager_, verifyToken(testing::_, testing::_)).WillByDefault(testing::Return(false));
    ON_CALL(callbacks_, encodeHeaders_(testing::_, testing::_)).WillByDefault(testing::Invoke(
          [](Http::HeaderMap& headers, bool)
            {
              // Assert url of response
              auto status = Http::Utility::getResponseStatus(headers);
              EXPECT_EQ(400, status);
            }));
    for(size_t i = 0; i < sizeof(scenarios)/sizeof(Http::TestHeaderMapImpl); i++) {
      EXPECT_CALL(callbacks_, encodeHeaders_(testing::_, testing::_)).Times(1);
      EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(scenarios[i], false));
    }
  } 

  TEST_F(HttpFilterOidcTest, TestDecodeHeadersRedirectsToAuthN) {
    // Verify requests:
    // - without and AuthZ header or session cookie are redirected to the AuthN endpoint.
    Http::TestHeaderMapImpl scenarios[] = {
      {{":method", "GET"}, {":path", "/"}, {":authority", "host"}, {"host", "host"}}
    };
    ON_CALL(state_store_, create(testing::_, testing::_)).WillByDefault(testing::Return("random"));
    ON_CALL(rng_, random()).WillByDefault(testing::Return(1001));
    for(size_t i = 0; i < sizeof(scenarios)/sizeof(Http::TestHeaderMapImpl); i++) {
      ON_CALL(callbacks_, encodeHeaders_(testing::_, testing::_)).WillByDefault(testing::Invoke(
            [](Http::HeaderMap& headers, bool)
              {
                // Assert url of response
                auto status = Http::Utility::getResponseStatus(headers);
                EXPECT_EQ(302, status);
                auto url = headers.get(Http::Headers::get().Location);
                ASSERT_TRUE(url != nullptr);
                auto params = Http::Utility::parseQueryString(url->value().c_str());
                auto type = params.find("response_type");
                auto scope = params.find("scope");
                auto client = params.find("client_id");
                auto state = params.find("state");
                auto nonce = params.find("nonce");
                auto redirect = params.find("redirect_uri");
                ASSERT_FALSE(type == params.end());
                ASSERT_FALSE(scope == params.end());
                ASSERT_FALSE(client == params.end());
                ASSERT_FALSE(state == params.end());
                ASSERT_FALSE(nonce == params.end());
                ASSERT_FALSE(redirect == params.end());
                EXPECT_STREQ("code", type->second.c_str());
                EXPECT_STREQ("openid%20email", scope->second.c_str());
                // TODO reinstate below
                //EXPECT_STREQ(config().client_id.c_str(), client->second.c_str());
                EXPECT_STREQ("random", state->second.c_str());
                EXPECT_STREQ("00000000000003e900000000000003e900000000000003e900000000000003e9", nonce->second.c_str());
                EXPECT_STREQ("https%3A%2F%2Fhost%2Foauth", redirect->second.c_str());
              }));
      EXPECT_CALL(callbacks_, encodeHeaders_(testing::_, testing::_)).Times(1);
      EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(scenarios[i], false));
    }
  } 
  
  TEST_F(HttpFilterOidcTest, TestRedeemTokenFailsWhenUnknownState) {
    // Verify that when we receive a request to redeem a token we do.
    Http::TestHeaderMapImpl headers{{":method", "GET"}, {":path", "/oauth?state=randomstate&code=01234567890"}, {":authority", "host"}, {"host", "host"}};
    ON_CALL(state_store_, get("randomstate")).WillByDefault(testing::Throw(Http::StateStore::Exception("expected")));
    ON_CALL(callbacks_, encodeHeaders_(testing::_, testing::_)).WillByDefault(testing::Invoke(
          [](Http::HeaderMap& headers, bool)
            {
              // Assert url of response
              auto status = Http::Utility::getResponseStatus(headers);
              EXPECT_EQ(400, status);
            }));
    EXPECT_CALL(callbacks_, encodeHeaders_(testing::_, testing::_)).Times(1);
    EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers, false));
  }
  
  TEST_F(HttpFilterOidcTest, TestRedeemTokenFailsWhenIncorrectMethod) {
    // Verify that when we receive a request to redeem a token we do.
    Http::TestHeaderMapImpl headers{{":method", "POST"}, {":path", "/oauth?state=randomstate&code=01234567890"}, {":authority", "host"}, {"host", "host"}};
    ON_CALL(callbacks_, encodeHeaders_(testing::_, testing::_)).WillByDefault(testing::Invoke(
          [](Http::HeaderMap& headers, bool)
            {
              // Assert url of response
              auto status = Http::Utility::getResponseStatus(headers);
              EXPECT_EQ(400, status);
            }));
    EXPECT_CALL(callbacks_, encodeHeaders_(testing::_, testing::_)).Times(1);
    EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers, false));
  }
  
  TEST_F(HttpFilterOidcTest, TestOnFailure) {
    // Verify that when we receive a request to redeem a token we do.
    ON_CALL(callbacks_, encodeHeaders_(testing::_, testing::_)).WillByDefault(testing::Invoke(
          [](Http::HeaderMap& headers, bool)
            {
              // Assert url of response
              auto status = Http::Utility::getResponseStatus(headers);
              EXPECT_EQ(500, status);
            }));
    EXPECT_CALL(callbacks_, encodeHeaders_(testing::_, testing::_)).Times(1);
    filter_->onFailure(Http::AsyncClient::FailureReason::Reset);
  }*/
} // Envoy
