/* Copyright 2017 Istio Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef JWT_AUTH_STORE_H
#define JWT_AUTH_STORE_H

#include "common/common/logger.h"
#include "envoy/server/filter_config.h"
#include "envoy/thread_local/thread_local.h"
#include "src/envoy/utils/config.pb.h"
#include "src/envoy/utils/pubkey_cache.h"

namespace Envoy {
namespace Utils {
namespace JwtAuth {

// Short hand for type for our proto list of JWTs.
typedef std::vector<Envoy::Utils::Config::JWT> JwtList_t;

// The JWT auth store object to store config and caches.
// It only has pubkey_cache for now. In the future it will have token cache.
// It is per-thread and stored in thread local.
class JwtAuthStore : public ThreadLocal::ThreadLocalObject {
 public:
  // Load the config from envoy config.
  JwtAuthStore(const JwtList_t& config)
      : config_(config), pubkey_cache_(config_) {}

  // Get the Config.
  const JwtList_t& config() const { return config_; }

  // Get the pubkey cache.
  PubkeyCache& pubkey_cache() { return pubkey_cache_; }

 private:
  // Store the config.
  const JwtList_t config_;
  // The public key cache, indexed by issuer.
  PubkeyCache pubkey_cache_;
};

// The factory to create per-thread auth store object.
class JwtAuthStoreFactory : public Logger::Loggable<Logger::Id::config> {
 public:
  JwtAuthStoreFactory(const JwtList_t& config,
                      Server::Configuration::FactoryContext& context)
      : config_(config), tls_(context.threadLocal().allocateSlot()) {
    tls_->set(
        [this](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
          return std::make_shared<JwtAuthStore>(config_);
        });
  }

  // Get per-thread auth store object.
  JwtAuthStore& store() { return tls_->getTyped<JwtAuthStore>(); }

 private:
  // The auth config.
  JwtList_t config_;
  // Thread local slot to store per-thread auth store
  ThreadLocal::SlotPtr tls_;
};

}  // namespace JwtAuth
}  // namespace Utils
}  // namespace Envoy

#endif  // JWT_AUTH_STORE_H
