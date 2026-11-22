// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "AncBackend.h"
#include "UdfpsHandler.h"

#include <aidl/android/hardware/biometrics/fingerprint/BnSession.h>
#include <aidl/android/hardware/biometrics/fingerprint/ISessionCallback.h>
#include <android/binder_ibinder.h>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>

namespace meizu::fingerprint {

namespace fp = aidl::android::hardware::biometrics::fingerprint;
namespace common = aidl::android::hardware::biometrics::common;
namespace keymaster = aidl::android::hardware::keymaster;

class Session final : public fp::BnSession {
  public:
    Session(std::shared_ptr<AncBackend> backend, int32_t userId,
            std::shared_ptr<fp::ISessionCallback> callback);
    ~Session() override;
    void initialize();
    void retire();
    bool isClosed() const { return mClosed.load(); }
    void cancel(uint64_t generation);

    ndk::ScopedAStatus generateChallenge() override;
    ndk::ScopedAStatus revokeChallenge(int64_t challenge) override;
    ndk::ScopedAStatus enroll(const keymaster::HardwareAuthToken& token,
                             std::shared_ptr<common::ICancellationSignal>* result) override;
    ndk::ScopedAStatus authenticate(int64_t operationId,
                                   std::shared_ptr<common::ICancellationSignal>* result) override;
    ndk::ScopedAStatus detectInteraction(std::shared_ptr<common::ICancellationSignal>* result) override;
    ndk::ScopedAStatus enumerateEnrollments() override;
    ndk::ScopedAStatus removeEnrollments(const std::vector<int32_t>& ids) override;
    ndk::ScopedAStatus getAuthenticatorId() override;
    ndk::ScopedAStatus invalidateAuthenticatorId() override;
    ndk::ScopedAStatus resetLockout(const keymaster::HardwareAuthToken& token) override;
    ndk::ScopedAStatus close() override;
    ndk::ScopedAStatus onPointerDown(int32_t id, int32_t x, int32_t y, float minor,
                                   float major) override;
    ndk::ScopedAStatus onPointerUp(int32_t id) override;
    ndk::ScopedAStatus onUiReady() override;
    ndk::ScopedAStatus authenticateWithContext(int64_t operationId,
                const common::OperationContext& context,
                std::shared_ptr<common::ICancellationSignal>* result) override;
    ndk::ScopedAStatus enrollWithContext(const keymaster::HardwareAuthToken& token,
                const common::OperationContext& context,
                std::shared_ptr<common::ICancellationSignal>* result) override;
    ndk::ScopedAStatus detectInteractionWithContext(const common::OperationContext& context,
                std::shared_ptr<common::ICancellationSignal>* result) override;
    ndk::ScopedAStatus onPointerDownWithContext(const fp::PointerContext& context) override;
    ndk::ScopedAStatus onPointerUpWithContext(const fp::PointerContext& context) override;
    ndk::ScopedAStatus onContextChanged(const common::OperationContext& context) override;
    ndk::ScopedAStatus onPointerCancelWithContext(const fp::PointerContext& context) override;
    ndk::ScopedAStatus setIgnoreDisplayTouches(bool ignore) override;

  private:
    enum class Operation { None, Authenticate, Enroll, Detect };
    using Work = std::function<void(Session&)>;
    void post(Work work);
    void closeInternal(bool notify);
    ndk::ScopedAStatus begin(Operation operation, uint64_t id,
                            std::optional<AncAuthToken> token,
                            std::shared_ptr<common::ICancellationSignal>* result);
    ndk::ScopedAStatus request(AncEvent::Type expected, std::function<int(AncBackend&)> call);
    void handle(AncEvent event);
    void error(fp::Error error, int32_t vendorCode = 0);
    void finish(bool authenticated = false);
    void invalidateTouch();
    void updateContext(const common::OperationContext& context);
    bool checkLockout();
    std::shared_ptr<Session> self();

    std::shared_ptr<AncBackend> mBackend;
    const int32_t mUserId;
    const std::shared_ptr<fp::ISessionCallback> mCallback;
    UdfpsHandler mUdfps;
    std::mutex mCloseMutex;
    std::atomic<bool> mClosed{false};
    std::atomic<bool> mRetired{false};
    std::atomic<uint64_t> mGeneration{0};
    std::atomic<uint64_t> mVendorGeneration{0};
    std::atomic<uint64_t> mTouchEpoch{0};
    std::atomic<bool> mIgnoreTouches{false};
    std::atomic<bool> mDisplayOff{false};
    Operation mOperation = Operation::None;
    uint64_t mActiveGeneration = 0;
    uint64_t mRequestGeneration = 0;
    std::optional<AncEvent::Type> mPending;
    bool mInitialized = false;
    AIBinder_DeathRecipient* mDeathRecipient = nullptr;
};

}  // namespace meizu::fingerprint
