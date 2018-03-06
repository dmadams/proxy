#include "mocks.h"

#include "gmock/gmock-matchers.h"

using namespace Envoy::Utils;

MockSessionManager::MockSessionManager() {
  ON_CALL(*this, createXsrfToken(testing::_)).WillByDefault(testing::Return(""));
  ON_CALL(*this, verifyToken(testing::_, testing::_)).WillByDefault(testing::Return(""));
}
