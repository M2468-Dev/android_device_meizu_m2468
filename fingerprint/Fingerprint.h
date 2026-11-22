// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "Session.h"
#include <aidl/android/hardware/biometrics/fingerprint/BnFingerprint.h>
#include <memory>
#include <mutex>
#include <vector>

namespace meizu::fingerprint {

class Fingerprint final : public fp::BnFingerprint {
  public:
    explicit Fingerprint(std::shared_ptr<AncBackend> backend) : mBackend(std::move(backend)) {}
    ndk::ScopedAStatus getSensorProps(std::vector<fp::SensorProps>* result) override;
    ndk::ScopedAStatus createSession(int32_t sensorId, int32_t userId,
                const std::shared_ptr<fp::ISessionCallback>& callback,
                std::shared_ptr<fp::ISession>* result) override;

  private:
    std::shared_ptr<AncBackend> mBackend;
    std::mutex mMutex;
    std::shared_ptr<Session> mSession;
};

}  // namespace meizu::fingerprint
