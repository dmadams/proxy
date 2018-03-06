#include "state_store.h"

#include <thread>

#include "envoy/runtime/runtime.h"
#include "test/mocks/runtime/mocks.h"

#include "gmock/gmock.h"

namespace Envoy {
  class StateStoreTest : public testing::Test {

    public:
      StateStoreTest()  {
        ON_CALL(rng_, random()).WillByDefault(testing::Return(1001));
        stateStoreImplPtr_.reset(
            new Http::StateStoreImpl(rng_));
      }

      typedef std::unique_ptr<Http::StateStoreImpl> StateStoreImplPtr;
      StateStoreImplPtr stateStoreImplPtr_;
      testing::NiceMock<Runtime::MockRandomGenerator> rng_;
  };
  
  TEST_F(StateStoreTest, TestState) {
    Http::StateStore::state_handle_t expectedHandle = "00000000000003e900000000000003e900000000000003e900000000000003e9"; 
    std::string context = "something";
    std::chrono::seconds fiveSeconds(5);
    std::chrono::seconds oneSecond(1);
    // Test basic creation
    EXPECT_EQ(expectedHandle, stateStoreImplPtr_->create(context, fiveSeconds).c_str());
    // Test basic retrieval
    EXPECT_EQ(context, stateStoreImplPtr_->get(expectedHandle).c_str());
    // Verify state cannot be redeemed twice.
    EXPECT_THROW(stateStoreImplPtr_->get(expectedHandle), Http::StateStore::Exception);
    // Verify state timeouts
    EXPECT_EQ(expectedHandle, stateStoreImplPtr_->create(context, oneSecond).c_str());
    std::this_thread::sleep_for (fiveSeconds);
    EXPECT_THROW(stateStoreImplPtr_->get(expectedHandle), Http::StateStore::Exception);
  }
} // namespace Envoy
