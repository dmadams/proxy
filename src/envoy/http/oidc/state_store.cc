#include "state_store.h"

#include <sstream>

#include "common/common/hex.h"
#include "common/common/logger.h"

using namespace Envoy;
using namespace Http;

namespace {
  StateStore::state_handle_t randomHandle(Runtime::RandomGenerator &rng) {
    std::ostringstream output;
    for(size_t i = 0; i < 32/sizeof(uint64_t); i++) {
      uint64_t part = rng.random();
      output << Hex::uint64ToHex(part);
    }
    return output.str();
  }
} //Unnamed namespace

LocalStateStoreImpl::LocalStateStoreImpl(Runtime::RandomGenerator &rng): rng_(rng) {
}

StateStore::state_handle_t LocalStateStoreImpl::create(const StateStore::StateContext &ctx, const std::chrono::seconds &expiry) {
  std::unique_lock<std::mutex> lock(storeMutex_);
  state_handle_t handle;
  do {
    handle = randomHandle(rng_);
  } while(store_.find(handle) != store_.end());
  auto calculated_expiry = std::chrono::steady_clock::now() + expiry;
  ContextWrapper wrapper{
    .ctx = ctx,
    .expiry = calculated_expiry
  };
  store_[handle] = wrapper;
  return handle;
}

StateStore::StateContext LocalStateStoreImpl::get(const StateStore::state_handle_t &handle) {
  std::unique_lock<std::mutex> lock(storeMutex_);
  auto it = store_.find(handle);
  // Does state exist?
  if(it == store_.end()) {
    return end();
  }
  auto result = it->second;
  store_.erase(it);
  // Has the state expired?
  auto diff = std::chrono::duration_cast<std::chrono::seconds>(result.expiry - std::chrono::steady_clock::now());
  if(diff <= std::chrono::seconds(0)) {
    return end();
  }
  return result.ctx;
}

/* TODO: Implement distributed state store using Redis
RedisStateStoreImpl::RedisStateStoreImpl(Runtime::RandomGenerator &rng): rng_(rng) {
}

StateStore::state_handle_t RedisStateStoreImpl::create(const StateContext &, const std::chrono::seconds &) {
  state_handle_t handle = 0;
  return handle;
}

StateStore::StateContext RedisStateStoreImpl::get(const StateStore::state_handle_t &) {
  return end();
}
 */