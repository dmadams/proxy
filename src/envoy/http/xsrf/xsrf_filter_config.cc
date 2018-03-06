#include <string>

#include "xsrf_filter.h"
#include "src/envoy/utils/session_manager.h"

#include "common/protobuf/utility.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"
#include "src/envoy/utils/config.pb.validate.h"

namespace Envoy {
  namespace Server {
    namespace Configuration {
      class XsrfFilterConfig : public NamedHttpFilterConfigFactory {
        private:
          HttpFilterFactoryCb createFilter(const Utils::Config::SessionManagerConfig& proto_config,
              FactoryContext& context) {
              Utils::SessionManager::SessionManagerPtr session_manager = std::make_shared<Utils::SessionManagerImpl>(proto_config);
              Upstream::ClusterManager& cm = context.clusterManager();  
              return [&cm, session_manager](Http::FilterChainFactoryCallbacks& callbacks) -> void {
                callbacks.addStreamDecoderFilter(
                  std::make_shared<Http::XsrfFilter>(cm, session_manager));
              };
          }
        public:
          HttpFilterFactoryCb createFilterFactory(const Json::Object &config, const std::string&,
              FactoryContext &context) override {
            Utils::Config::SessionManagerConfig proto_config;
            MessageUtil::loadFromJson(config.asJsonString(), proto_config);
            return createFilter(proto_config, context);
          }

          HttpFilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message &proto_config,
              const std::string&,
              FactoryContext &context) override {
              return createFilter(
                MessageUtil::downcastAndValidate<const Utils::Config::SessionManagerConfig&>(proto_config), context);
          }

          ProtobufTypes::MessagePtr createEmptyConfigProto() override {
            return ProtobufTypes::MessagePtr{new Envoy::ProtobufWkt::Empty()}; 
          }

          std::string name() override { return "xsrf"; }
      };

      static Registry::RegisterFactory<XsrfFilterConfig, NamedHttpFilterConfigFactory>
        register_;

    } // Configuration
  } // Server
} // Envoy
