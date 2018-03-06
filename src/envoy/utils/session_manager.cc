#include "session_manager.h"

#include <cstring>

#include "common/common/base64.h"

#include "openssl/evp.h"
#include "openssl/hmac.h"

namespace Envoy {
  namespace Utils {
    SessionManagerImpl::SessionManagerImpl(const key_t &key) {
      std::memcpy(key_, key, sizeof(key_));
    }
    
    SessionManagerImpl::SessionManagerImpl(const Utils::Config::SessionManagerConfig &config) {
      auto characters = Base64::decode(config.key());
      if(characters.size() != sizeof(key_)) {
        throw std::runtime_error("expected session_protection_key to be 32 bytes after base64 decode");
      }
      std::memcpy(key_, characters.c_str(), sizeof(key_));
    }

    SessionManager::~SessionManager() {
    }

    std::string SessionManagerImpl::hmac(const SessionManager::jwt_t &jwt) const {
      uint8_t mac[EVP_MAX_MD_SIZE];
      unsigned int length;
      const EVP_MD *digester = EVP_sha256();
      auto macd = HMAC(digester, key_, sizeof(key_), reinterpret_cast<const unsigned char *>(jwt.c_str()), jwt.size()+1, mac, &length);
      if (!macd) {
        throw SessionManager::Exception("Token binding failure");
      }
      return Base64::encode(reinterpret_cast<char *>(macd), length);
    }
    
    SessionManager::token_t SessionManagerImpl::createXsrfToken(const SessionManager::jwt_t &jwt) {
      auto token = hmac(jwt);
      return token;
    }

    bool SessionManagerImpl::verifyToken(const SessionManager::jwt_t &jwt, const std::string &token) const {
      auto calculated = hmac(jwt);
      return token == calculated;
    }
  } // Http
} // Envoy
