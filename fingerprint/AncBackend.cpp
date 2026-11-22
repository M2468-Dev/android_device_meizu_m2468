// SPDX-License-Identifier: Apache-2.0
#define LOG_TAG "MeizuFingerprint"
#include "AncBackend.h"

#include <android/log.h>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <dlfcn.h>
#include <utility>

namespace meizu::fingerprint {

struct AncBackend::Callbacks {
    void (*challengeGenerated)(void*, uint64_t);
    void (*challengeRevoked)(void*, uint64_t);
    void (*authenticatorId)(void*, uint64_t);
    void (*authenticatorIdInvalidated)(void*, uint64_t);
    void (*enrollment)(void*, uint32_t, uint64_t, uint32_t);
    void (*acquired)(void*, uint32_t);
    void (*authentication)(void*, uint32_t, uint64_t, const void*, uint32_t);
    void (*error)(void*, uint32_t);
    void (*removed)(void*, const uint32_t*, uint32_t);
    void (*enumerated)(void*, const uint32_t*, uint32_t);
    void* reserved0;
    void (*lockoutTimed)(void*, uint64_t);
    void (*lockoutPermanent)();
    void* reserved1;
};

struct AncBackend::ExtensionCallbacks {
    void (*result)(void*, uint32_t, uint32_t, const void*, uint32_t);
};

struct AncBackend::Api {
    void* (*getDevice)();
    int (*initialize)(void*);
    int (*deinitialize)(void*);
    void (*setNotify)(void*, const Callbacks*);
    void (*setExtension)(void*, const ExtensionCallbacks*);
    int (*setActiveGroup)(void*, uint32_t, const char*);
    int (*generateChallenge)(void*);
    int (*revokeChallenge)(void*, uint64_t);
    int (*enroll)(void*, const AncAuthToken*);
    int (*authenticate)(void*, uint64_t);
    int (*enumerate)(void*);
    int (*remove)(void*, const uint32_t*, uint32_t);
    int (*getAuthenticatorId)(void*);
    int (*invalidateAuthenticatorId)(void*);
    int (*resetLockout)(void*, const AncAuthToken*);
    int (*cancel)(void*);
    void (*pointerDown)(void*, int32_t, int32_t, int32_t, float, float);
    void (*pointerUp)(void*, int32_t);
    // Stock JIIOV forwards device, command, payload, size, output and outputSize.
    int (*executeCommand)(void*, int32_t, const uint8_t*, uint32_t, uint8_t**, uint32_t*);
};

std::atomic<AncBackend*> AncBackend::sInstance{nullptr};

const AncBackend::Callbacks AncBackend::sCallbacks{
    [](void*, uint64_t value) { emit({AncEvent::Type::ChallengeGenerated, value}); },
    [](void*, uint64_t value) { emit({AncEvent::Type::ChallengeRevoked, value}); },
    [](void*, uint64_t value) { emit({AncEvent::Type::AuthenticatorId, value}); },
    [](void*, uint64_t value) { emit({AncEvent::Type::AuthenticatorIdInvalidated, value}); },
    [](void*, uint32_t id, uint64_t, uint32_t remaining) {
        AncEvent event{AncEvent::Type::Enrollment};
        event.id = id;
        event.remaining = remaining;
        emit(std::move(event), remaining == 0);
    },
    [](void*, uint32_t code) { emit({AncEvent::Type::Acquired, code}); },
    [](void*, uint32_t id, uint64_t, const void* token, uint32_t size) {
        if (id && (!token || size != sizeof(AncAuthToken))) {
            emit({AncEvent::Type::Error, 1}, true);
            return;
        }
        AncEvent event{AncEvent::Type::Authentication};
        event.id = id;
        if (id) std::memcpy(&event.token, token, sizeof(event.token));
        emit(std::move(event), id != 0);
    },
    [](void*, uint32_t code) { emit({AncEvent::Type::Error, code}, true); },
    [](void*, const uint32_t* ids, uint32_t count) {
        if (count > 5 || (count && !ids)) {
            emit({AncEvent::Type::Error, 1});
            return;
        }
        AncEvent event{AncEvent::Type::Removed};
        for (uint32_t i = 0; i < count; ++i) event.ids.push_back(ids[i]);
        emit(std::move(event));
    },
    [](void*, const uint32_t* ids, uint32_t count) {
        if (count > 5 || (count && !ids)) {
            emit({AncEvent::Type::Error, 1});
            return;
        }
        AncEvent event{AncEvent::Type::Enumerated};
        for (uint32_t i = 0; i < count; ++i) event.ids.push_back(ids[i]);
        emit(std::move(event));
    },
    nullptr,
    [](void*, uint64_t duration) { emit({AncEvent::Type::LockoutTimed, duration}, true); },
    [] { emit({AncEvent::Type::LockoutPermanent}, true); },
    nullptr,
};

const AncBackend::ExtensionCallbacks AncBackend::sExtensionCallbacks{
    [](void*, uint32_t, uint32_t, const void*, uint32_t) {},
};

AncBackend::AncBackend() {
    static_assert(offsetof(Callbacks, lockoutTimed) == 0x58);
    static_assert(offsetof(Callbacks, lockoutPermanent) == 0x60);
}

AncBackend::~AncBackend() {
    setListener({});
    sInstance.store(nullptr);
    if (mInitialized) mApi->deinitialize(mDevice);
    delete mApi;
    // ANC may retain library-owned thread-local destructors until process exit.
}

bool AncBackend::open() {
    if (mInitialized) return true;
    mLibrary = dlopen("/vendor/lib64/anc.hal.so", RTLD_NOW | RTLD_LOCAL);
    if (!mLibrary) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Load ANC: %s", dlerror());
        return false;
    }
    mApi = new Api{};
#define ANC_LOAD(member, symbol)                                                               \
    mApi->member = reinterpret_cast<decltype(mApi->member)>(dlsym(mLibrary, symbol));             \
    if (!mApi->member) {                                                                       \
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Missing ANC entry: %s", symbol);       \
        return false;                                                                         \
    }
    ANC_LOAD(getDevice, "GetFingerprintDevice");
    ANC_LOAD(initialize, "InitFingerprintDevice");
    ANC_LOAD(deinitialize, "DeinitFingerprintDevice");
    ANC_LOAD(setNotify, "AncSetNotifyCallback");
    ANC_LOAD(setExtension, "AncSetExtensionCallback");
    ANC_LOAD(setActiveGroup, "AncSetActiveGroup");
    ANC_LOAD(generateChallenge, "AncGenerateChallenge");
    ANC_LOAD(revokeChallenge, "AncRevokeChallenge");
    ANC_LOAD(enroll, "AncEnroll");
    ANC_LOAD(authenticate, "AncAuthenticate");
    ANC_LOAD(enumerate, "AncEnumerate");
    ANC_LOAD(remove, "AncRemove");
    ANC_LOAD(getAuthenticatorId, "AncGetAuthenticatorId");
    ANC_LOAD(invalidateAuthenticatorId, "AncInvalidateAuthenticatorId");
    ANC_LOAD(resetLockout, "AncResetLockout");
    ANC_LOAD(cancel, "AncCancel");
    ANC_LOAD(pointerDown, "AncOnPointerDown");
    ANC_LOAD(pointerUp, "AncOnPointerUp");
    ANC_LOAD(executeCommand, "AncExcuteCommand");
#undef ANC_LOAD
    mDevice = mApi->getDevice();
    if (!mDevice) return false;
    sInstance.store(this);
    int rc = mApi->initialize(mDevice);
    if (rc) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Initialize ANC: %d", rc);
        sInstance.store(nullptr);
        return false;
    }
    // Match the JIIOV loader: initialize the ANC device before installing callbacks.
    mApi->setNotify(mDevice, &sCallbacks);
    mApi->setExtension(mDevice, &sExtensionCallbacks);
    mInitialized = true;
    return true;
}

void AncBackend::setListener(Listener listener) {
    std::lock_guard lock(mListenerMutex);
    mListener = std::move(listener);
}

void AncBackend::emit(AncEvent event, bool terminal) {
    auto* backend = sInstance.load();
    if (!backend) return;
    // Publish to the current session before releasing a cancel/user-switch barrier.
    backend->dispatch(std::move(event));
    if (terminal) {
        {
            std::lock_guard lock(backend->mRunningMutex);
            backend->mRunning = false;
        }
        backend->mIdle.notify_all();
    }
}

void AncBackend::dispatch(AncEvent event) {
    Listener listener;
    {
        std::lock_guard lock(mListenerMutex);
        listener = mListener;
    }
    if (listener) listener(std::move(event));
}

int AncBackend::setActiveGroup(uint32_t userId, const char* path) {
    return mApi->setActiveGroup(mDevice, userId, path);
}
int AncBackend::generateChallenge() { return mApi->generateChallenge(mDevice); }
int AncBackend::revokeChallenge(uint64_t value) { return mApi->revokeChallenge(mDevice, value); }
int AncBackend::enumerate() { return mApi->enumerate(mDevice); }
int AncBackend::getAuthenticatorId() { return mApi->getAuthenticatorId(mDevice); }
int AncBackend::invalidateAuthenticatorId() { return mApi->invalidateAuthenticatorId(mDevice); }
int AncBackend::resetLockout(const AncAuthToken& token) {
    return mApi->resetLockout(mDevice, &token);
}
int AncBackend::remove(const std::vector<int32_t>& ids) {
    if (ids.size() > 5) return -EINVAL;
    std::vector<uint32_t> values(ids.begin(), ids.end());
    return mApi->remove(mDevice, values.data(), values.size());
}

int AncBackend::enroll(const AncAuthToken& token) {
    {
        std::lock_guard lock(mRunningMutex);
        if (mRunning) return -EBUSY;
        mRunning = true;
    }
    int rc = mApi->enroll(mDevice, &token);
    if (rc) {
        std::lock_guard lock(mRunningMutex);
        mRunning = false;
    }
    return rc;
}

int AncBackend::authenticate(uint64_t id) {
    {
        std::lock_guard lock(mRunningMutex);
        if (mRunning) return -EBUSY;
        mRunning = true;
    }
    int rc = mApi->authenticate(mDevice, id);
    if (rc) {
        std::lock_guard lock(mRunningMutex);
        mRunning = false;
    }
    return rc;
}

bool AncBackend::cancelAndDrain() {
    {
        std::lock_guard lock(mRunningMutex);
        if (!mRunning) return true;
    }
    int rc = mApi->cancel(mDevice);
    std::unique_lock lock(mRunningMutex);
    bool idle = mIdle.wait_for(lock, std::chrono::seconds(2), [this] { return !mRunning; });
    if (!idle) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "ANC cancel did not finish: %d", rc);
    return idle;
}

void AncBackend::pointerDown(int32_t id, int32_t x, int32_t y, float minor, float major) {
    mApi->pointerDown(mDevice, id, x, y, minor, major);
}
void AncBackend::pointerUp(int32_t id) { mApi->pointerUp(mDevice, id); }
bool AncBackend::illuminationReady() {
    uint8_t* output = nullptr;
    uint32_t outputSize = 0;
    int rc = mApi->executeCommand(mDevice, 20015, nullptr, 0, &output, &outputSize);
    if (rc)
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "ANC UI-ready command failed: %d", rc);
    return rc == 0;
}

}  // namespace meizu::fingerprint
