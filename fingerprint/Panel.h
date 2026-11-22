// SPDX-License-Identifier: Apache-2.0
#pragma once

namespace meizu::fingerprint {

class Panel {
  public:
    static bool setFod(bool enabled);
    static bool setHbm(bool enabled);
    static bool setResult(bool authenticated);
    static bool isReady();
};

}  // namespace meizu::fingerprint
