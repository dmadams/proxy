#pragma once

#include "session_manager.h"

#include "gmock/gmock.h"

namespace Envoy {
  namespace Utils {
    class MockSessionManager : public SessionManager {
      public:
        MockSessionManager();

        MOCK_METHOD1(createXsrfToken, SessionManager::token_t (const SessionManager::jwt_t &jwt));
        MOCK_CONST_METHOD2(verifyToken, bool (const SessionManager::jwt_t &jwt, const SessionManager::token_t &token));
    };
  } // namespace Http
} // namepace Envoy
