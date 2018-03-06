#pragma once

#include "envoy/http/header_map.h"

namespace Envoy {
namespace Utils {
class Constants {
  public:
    static const Http::LowerCaseString &JwtPayloadKey();
}; // Constants
} // namespace Utils
} // namespace Envoy
