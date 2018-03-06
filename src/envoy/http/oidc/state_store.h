#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <string>

#include "envoy/common/exception.h"
#include "envoy/common/pure.h"
#include "envoy/runtime/runtime.h"

// TODO: We need to clear up expired states asynchronously somewhere.
namespace Envoy {
namespace Http {
  class StateStore{
    public:
      typedef std::string state_handle_t;
      struct StateContext {
        std::string idp_;
        std::string nonce_;
        std::string hostname_;

        StateContext(){}
        StateContext(const std::string &idp, const std::string& nonce, const std::string& hostname)
            : idp_(idp), nonce_(nonce), hostname_(hostname){}

        bool operator == (const StateContext& rhs) const {
          return nonce_ == rhs.nonce_;
        }

        bool operator != (const StateContext& rhs) const {
          return nonce_ != rhs.nonce_;
        }
      };
      /* unknown state identifier.
       * @return the identity of the unknown state.
       */
      const StateContext &end() const {
        static StateContext zero = {};
        return zero;
      }

      virtual ~StateStore(){};
      /* create stores the given ctx parameter returning a handle that can be used to retrieve it later.
       * @param ctx the state to store.
       * @param expiry the expiration of the state.
       * @return a handle to the state stored.
       */
      virtual state_handle_t create(const StateContext &ctx, const std::chrono::seconds &expiry) PURE;
      /* get returns the state for the given handle and removing it from the state store.
       * If no state is associated with the given handle an exception is raised.
       * @param handle the handle to the stored state.
       * @return the state context associated with the handle.
       */
      virtual StateContext get(const state_handle_t &handle) PURE;
  };

  class LocalStateStoreImpl: public StateStore {
    private:
      struct ContextWrapper {
        StateContext ctx;
        std::chrono::steady_clock::time_point expiry;
      };
      std::map<StateStore::state_handle_t, ContextWrapper> store_;
      std::mutex storeMutex_;
      Runtime::RandomGenerator &rng_;
    public:
      LocalStateStoreImpl(Runtime::RandomGenerator &rng);

      StateStore::state_handle_t create(const StateContext &ctx, const std::chrono::seconds &expiry);
      StateContext get(const StateStore::state_handle_t &handle);
  };

  /* TODO: Implement distributed state store using Redis
  class RedisStateStoreImpl: public StateStore {
    private:
      Runtime::RandomGenerator &rng_;
    public:
      RedisStateStoreImpl(Runtime::RandomGenerator &rng);

      StateStore::state_handle_t create(const StateContext &ctx, const std::chrono::seconds &expiry);
      StateStore::StateContext get(const StateStore::state_handle_t &handle);
  };
   */
} // namespace Http
} // namespace Envoy
