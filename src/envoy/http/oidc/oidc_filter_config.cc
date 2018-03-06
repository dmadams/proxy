#include <regex>
#include <string>

#include "oidc_filter.h"
#include "state_store.h"
#include "src/envoy/utils/session_manager.h"
#include "src/envoy/utils/auth_store.h"

#include "common/protobuf/utility.h"
#include "common/runtime/runtime_impl.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "google/protobuf/util/json_util.h"
#include "src/envoy/http/oidc/config.pb.validate.h"

namespace Envoy {
namespace Server {
namespace Configuration {

  class OidcFilterConfig : public NamedHttpFilterConfigFactory {
    private:
      static Runtime::RandomGenerator &getRng() {
        static Runtime::RandomGeneratorImpl rng_;
        return rng_;
      }

      static Http::StateStore &getStateStore() {
        static Http::LocalStateStoreImpl state_store_(getRng());
        return state_store_;
      }


      HttpFilterFactoryCb createFilter(const Http::Oidc::Config::OidcConfig& proto_config,
          FactoryContext& context) {
        Utils::JwtAuth::JwtList_t jwts;
        for(const auto &matchesRef : proto_config.matches()) {
          const Utils::Config::JWT &jwt = matchesRef.second.idp().jwt_config();
          jwts.push_back(jwt);
        }
        auto auth_store_factory = std::make_shared<Utils::JwtAuth::JwtAuthStoreFactory>(
            jwts, //TODO is this right
            context);
        Utils::SessionManager::SessionManagerPtr session_manager = std::make_shared<Utils::SessionManagerImpl>(proto_config.session_manager_config());
        Upstream::ClusterManager& cm = context.clusterManager();
        return [this, &cm, proto_config, auth_store_factory, session_manager](Http::FilterChainFactoryCallbacks& callbacks) -> void {
          callbacks.addStreamFilter(
            std::make_shared<Http::OidcFilter>(cm,
              session_manager,
              getStateStore(),
              getRng(),
              auth_store_factory->store(),
              proto_config));
        };
      }
    public:
      OidcFilterConfig() {
      }

      HttpFilterFactoryCb createFilterFactory(const Json::Object &config, const std::string&,
          FactoryContext &context) override {
        Http::Oidc::Config::OidcConfig proto_config;
        MessageUtil::loadFromJson(config.asJsonString(), proto_config);
        return createFilter(proto_config, context);
      }

      HttpFilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message &proto_config,
          const std::string&,
          FactoryContext &context) override {
        return createFilter(
            MessageUtil::downcastAndValidate<const Http::Oidc::Config::OidcConfig&>(proto_config), context);
      }

      ProtobufTypes::MessagePtr createEmptyConfigProto() override {
        return ProtobufTypes::MessagePtr{new Envoy::ProtobufWkt::Empty()};
      }

      std::string name() override { return "oidc"; }
  };

  static Registry::RegisterFactory<OidcFilterConfig, NamedHttpFilterConfigFactory>
    register_;
} // Configuration
} // Server
} // Envoy
