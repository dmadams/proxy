#include "mocks.h"

#include "gmock/gmock-matchers.h"

using namespace Envoy;
using namespace Http;

MockStateStore::MockStateStore() {
  ON_CALL(*this, create(testing::_, testing::_)).WillByDefault(testing::Return("random"));
  ON_CALL(*this, get(testing::_)).WillByDefault(testing::Return(StateStore::StateContext{.hostname = "", .nonce = ""}));
}
