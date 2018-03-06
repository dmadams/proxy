#include "constants.h"

namespace Envoy {
namespace Utils {
namespace {
  Http::LowerCaseString kJwtPayloadKey("sec-istio-auth-userinfo");
} // unnamed namespace

const Http::LowerCaseString &Constants::JwtPayloadKey() {
  return kJwtPayloadKey;
}

} // namespace Utils
} // namespace Envoy
