#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <string>

#include "src/envoy/utils/config.pb.h"

#include "envoy/common/exception.h"
#include "envoy/common/pure.h"
#include "envoy/runtime/runtime.h"

namespace Envoy {
  namespace Utils {
    class SessionManager
    {
      public:
        typedef uint8_t key_t[256/8]; // If there's ever a binding algorithm > 256 bits then this needs enlarging.
        typedef std::shared_ptr<SessionManager> SessionManagerPtr;
        
        class Exception: public EnvoyException
        {
          public:
            Exception(const std::string &message) : EnvoyException(message){}
        };

        typedef std::string jwt_t;
        typedef std::string token_t;
        virtual ~SessionManager();
        /* createXsrfToken creates a XSRF token bound to the given JWT.
         * @param jwt the token to be bound.
         * @return the XSRF token.
         */
        virtual token_t createXsrfToken(const jwt_t &jwt) PURE;
        /* verifyToken vefify that the given token is bound to the given jwt
         * @param jwt the jwt
         * @param the token
         * @return true or false
         */
        virtual bool verifyToken(const jwt_t &jwt, const token_t &token) const PURE;
    };

    class SessionManagerImpl : public SessionManager
    {
      public:
        SessionManagerImpl(const key_t &key);
        explicit SessionManagerImpl(const Utils::Config::SessionManagerConfig &config);
        SessionManager::token_t createXsrfToken(const SessionManager::jwt_t &jwt);
        bool verifyToken(const SessionManager::jwt_t &jwt, const SessionManager::token_t &token) const;
      private:
        SessionManager::key_t key_;
        std::string hmac(const SessionManager::jwt_t &jwt) const;
    };
  } // Http
} // Envoy
