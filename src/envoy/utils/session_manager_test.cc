#include "session_manager.h"
#include "src/envoy/utils/config.pb.h"

#include "gmock/gmock.h"

namespace Envoy {
namespace Utils {
  class SessionManagerTest : public testing::Test {

    public:
      SessionManagerTest()  {
        static const SessionManager::key_t key_ = {0};
        sessionManagerImplPtr_.reset(
            new SessionManagerImpl(key_));
      }

      typedef std::unique_ptr<SessionManagerImpl> SessionManagerImplPtr;
      SessionManagerImplPtr sessionManagerImplPtr_;
  };
  
    TEST_F(SessionManagerTest, TestConstructorWithConfig) {
      static const std::string key = "pkb8+yUNwrVoYGaAwU9p/h6Mz0ryYwKoG1Irma6q8UY=";
      Utils::Config::SessionManagerConfig config;
      config.set_key(key);
      SessionManagerImpl manager(config);
    }
  
    TEST_F(SessionManagerTest, TestTokens) {
    auto token1 = sessionManagerImplPtr_->createXsrfToken("something");
    EXPECT_EQ(44, token1.size()); // base64 encoded 32-byte digest
    EXPECT_EQ(true, sessionManagerImplPtr_->verifyToken("something", token1));
    EXPECT_EQ(false, sessionManagerImplPtr_->verifyToken("somethingelse", token1));
  }
} // namespace Utils
} // namespace Envoy
