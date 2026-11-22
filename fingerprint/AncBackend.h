// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "SerialExecutor.h"

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <vector>

namespace meizu::fingerprint {

// The ANC wire token uses native-order IDs and network-order type/timestamp.
struct __attribute__((packed)) AncAuthToken {
    uint8_t version = 0;
    uint64_t challenge = 0;
    uint64_t userId = 0;
    uint64_t authenticatorId = 0;
    uint32_t authenticatorType = 0;
    uint64_t timestamp = 0;
    std::array<uint8_t, 32> mac{};
};
static_assert(sizeof(AncAuthToken) == 69);

struct AncEvent {
    enum class Type {
        ChallengeGenerated, ChallengeRevoked, AuthenticatorId, AuthenticatorIdInvalidated,
        Enrollment, Acquired, Authentication, Error, Removed, Enumerated,
        LockoutTimed, LockoutPermanent,
    };
    Type type;
    uint64_t value = 0;
    uint32_t id = 0;
    uint32_t remaining = 0;
    AncAuthToken token{};
    std::vector<int32_t> ids;
};

class AncBackend {
  public:
    using Listener = std::function<void(AncEvent)>;
    struct Lockout {
        bool permanent = false;
        SerialExecutor::Clock::time_point until{};
        uint64_t generation = 0;
    };

    AncBackend();
    ~AncBackend();
    bool open();
    void setListener(Listener listener);
    int setActiveGroup(uint32_t userId, const char* path);
    int generateChallenge();
    int revokeChallenge(uint64_t challenge);
    int enroll(const AncAuthToken& token);
    int authenticate(uint64_t operationId);
    int enumerate();
    int remove(const std::vector<int32_t>& ids);
    int getAuthenticatorId();
    int invalidateAuthenticatorId();
    int resetLockout(const AncAuthToken& token);
    bool cancelAndDrain();
    void pointerDown(int32_t id, int32_t x, int32_t y, float minor, float major);
    void pointerUp(int32_t id);
    bool illuminationReady();

    SerialExecutor executor;
    // Accessed only by executor, retained across AIDL sessions and user switches.
    std::map<int32_t, Lockout> lockouts;

  private:
    struct Callbacks;
    struct ExtensionCallbacks;
    struct Api;
    static void emit(AncEvent event, bool terminal = false);
    void dispatch(AncEvent event);
    void* mLibrary = nullptr;
    void* mDevice = nullptr;
    Api* mApi = nullptr;
    bool mInitialized = false;
    std::mutex mListenerMutex;
    Listener mListener;
    std::mutex mRunningMutex;
    std::condition_variable mIdle;
    bool mRunning = false;
    static std::atomic<AncBackend*> sInstance;
    static const Callbacks sCallbacks;
    static const ExtensionCallbacks sExtensionCallbacks;
};

}  // namespace meizu::fingerprint
