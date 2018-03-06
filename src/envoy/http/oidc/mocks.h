#pragma once

#include "state_store.h"

#include "gmock/gmock.h"

namespace Envoy {
  namespace Http {
    class MockStateStore : public StateStore {
      public:
        MockStateStore();

        MOCK_METHOD2(create, StateStore::state_handle_t (const StateStore::StateContext &, const std::chrono::seconds &));
        MOCK_METHOD1(get, StateStore::StateContext (const StateStore::state_handle_t &));
    };
  } // namespace Http
} // namepace Envoy
