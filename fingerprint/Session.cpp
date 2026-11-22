// SPDX-License-Identifier: Apache-2.0
#define LOG_TAG "MeizuFingerprint"
#include "Session.h"

#include <aidl/android/hardware/biometrics/common/BnCancellationSignal.h>
#include <aidl/android/hardware/biometrics/common/DisplayState.h>
#include <android/log.h>
#include <endian.h>
#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <limits>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <unistd.h>

namespace meizu::fingerprint {
namespace {
using Clock = SerialExecutor::Clock;
using namespace std::chrono_literals;

class CancellationSignal final : public common::BnCancellationSignal {
  public:
    CancellationSignal(std::weak_ptr<Session> session, uint64_t generation)
        : mSession(std::move(session)), mGeneration(generation) {}
    ndk::ScopedAStatus cancel() override {
        if (auto session = mSession.lock()) session->cancel(mGeneration);
        return ndk::ScopedAStatus::ok();
    }
  private:
    std::weak_ptr<Session> mSession;
    uint64_t mGeneration;
};

std::optional<AncAuthToken> toAnc(const keymaster::HardwareAuthToken& token) {
    if (token.mac.size() != 32) return std::nullopt;
    AncAuthToken out;
    out.challenge = token.challenge;
    out.userId = token.userId;
    out.authenticatorId = token.authenticatorId;
    out.authenticatorType = htobe32(static_cast<uint32_t>(token.authenticatorType));
    out.timestamp = htobe64(token.timestamp.milliSeconds);
    std::copy(token.mac.begin(), token.mac.end(), out.mac.begin());
    return out;
}

keymaster::HardwareAuthToken fromAnc(const AncAuthToken& token) {
    keymaster::HardwareAuthToken out;
    out.challenge = token.challenge;
    out.userId = token.userId;
    out.authenticatorId = token.authenticatorId;
    out.authenticatorType = static_cast<keymaster::HardwareAuthenticatorType>(
            be32toh(token.authenticatorType));
    out.timestamp.milliSeconds = be64toh(token.timestamp);
    out.mac.assign(token.mac.begin(), token.mac.end());
    return out;
}

void fatalBackend() {
    // An undrained ANC worker cannot safely be reassigned to another user/session.
    __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Restarting after stalled ANC operation");
    _exit(1);
}
}  // namespace

Session::Session(std::shared_ptr<AncBackend> backend, int32_t userId,
                 std::shared_ptr<fp::ISessionCallback> callback)
    : mBackend(std::move(backend)), mUserId(userId), mCallback(std::move(callback)),
      mUdfps(*mBackend) {}

Session::~Session() {
    if (mDeathRecipient) AIBinder_DeathRecipient_delete(mDeathRecipient);
}

std::shared_ptr<Session> Session::self() { return ref<Session>(); }

void Session::post(Work work) {
    mBackend->executor.post([session = self(), work = std::move(work)] {
        if (!session->mClosed) work(*session);
    });
}

void Session::initialize() {
    auto weak = std::weak_ptr<Session>(self());
    mDeathRecipient = AIBinder_DeathRecipient_new([](void* cookie) {
        if (auto session = static_cast<std::weak_ptr<Session>*>(cookie)->lock()) session->retire();
    });
    AIBinder_DeathRecipient_setOnUnlinked(mDeathRecipient, [](void* cookie) {
        delete static_cast<std::weak_ptr<Session>*>(cookie);
    });
    binder_status_t rc = AIBinder_linkToDeath(mCallback->asBinder().get(), mDeathRecipient,
                                             new std::weak_ptr<Session>(weak));
    if (rc != STATUS_OK) {
        retire();
        return;
    }
    mUdfps.setReadyCallback([weak, backend = mBackend](uint64_t epoch, bool ready) {
        // Keep Session ownership on the executor: the ready thread must never
        // release the final reference and then try to join itself in destruction.
        backend->executor.post([weak, epoch, ready] {
            auto session = weak.lock();
            if (!session || session->mClosed) return;
            auto& s = *session;
            if (s.mOperation == Operation::None || s.mTouchEpoch != epoch ||
                s.mIgnoreTouches || s.mDisplayOff)
                return;
            if (ready) {
                if (s.mUdfps.deliverReady(epoch) == UdfpsHandler::ReadyResult::Failed) {
                    s.error(fp::Error::UNABLE_TO_PROCESS);
                    if (!s.mBackend->cancelAndDrain()) fatalBackend();
                }
            } else {
                __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                                    "HBM-ready timed out for user %d", s.mUserId);
                s.error(fp::Error::TIMEOUT);
                if (!s.mBackend->cancelAndDrain()) fatalBackend();
            }
        });
    });
    post([weak](Session& s) {
        // All session setup, vendor calls and callbacks share this executor.
        if (!s.mBackend->cancelAndDrain()) fatalBackend();
        s.mBackend->setListener({});
        s.mUdfps.finishOperation();
        std::string parent = "/data/vendor_de/" + std::to_string(s.mUserId);
        std::string path = parent + "/fpdata";
        if ((mkdir(parent.c_str(), 0770) && errno != EEXIST) ||
            (mkdir(path.c_str(), 0700) && errno != EEXIST)) {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Create storage %s: %s",
                                path.c_str(), strerror(errno));
            s.error(fp::Error::HW_UNAVAILABLE);
            return;
        }
        int groupResult = s.mBackend->setActiveGroup(s.mUserId, path.c_str());
        if (groupResult) {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Set ANC user %d: %d",
                                s.mUserId, groupResult);
            s.error(fp::Error::HW_UNAVAILABLE);
            return;
        }
        s.mBackend->setListener([weak](AncEvent event) {
            auto session = weak.lock();
            if (!session) return;
            uint64_t generation = session->mVendorGeneration.load();
            session->post([generation, event = std::move(event)](Session& current) mutable {
                if (generation != current.mVendorGeneration) return;
                current.handle(std::move(event));
            });
        });
        s.mInitialized = true;
    });
}

void Session::invalidateTouch() {
    ++mTouchEpoch;
    mUdfps.invalidateReady();
}

void Session::finish(bool authenticated) {
    invalidateTouch();
    mOperation = Operation::None;
    mUdfps.finishOperation(authenticated);
}

void Session::error(fp::Error code, int32_t vendorCode) {
    __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Fingerprint error: user=%d error=%d vendor=%d",
                        mUserId, static_cast<int32_t>(code), vendorCode);
    finish();
    ++mRequestGeneration;
    mPending.reset();
    // Framework clears its session asynchronously after HW_UNAVAILABLE. Keep
    // the binder alive for in-flight UI/context calls until close/replacement.
    if (code == fp::Error::HW_UNAVAILABLE) mInitialized = false;
    mCallback->onError(code, vendorCode);
}

bool Session::checkLockout() {
    auto& lockout = mBackend->lockouts[mUserId];
    if (lockout.permanent) {
        mCallback->onLockoutPermanent();
        return true;
    }
    if (lockout.until > Clock::now()) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                lockout.until - Clock::now()).count();
        mCallback->onLockoutTimed(std::max<int64_t>(remaining, 1));
        return true;
    }
    if (lockout.until != Clock::time_point{}) {
        lockout.until = {};
        mCallback->onLockoutCleared();
    }
    return false;
}

ndk::ScopedAStatus Session::begin(Operation operation, uint64_t id,
        std::optional<AncAuthToken> token, std::shared_ptr<common::ICancellationSignal>* result) {
    // Always return a valid signal, including calls racing with session close.
    // A stale session must not throw a Java RuntimeException into system_server.
    if (mClosed) {
        *result = ndk::SharedRefBase::make<CancellationSignal>(self(), mGeneration.load());
        return ndk::ScopedAStatus::ok();
    }
    uint64_t generation = ++mGeneration;
    invalidateTouch();
    *result = ndk::SharedRefBase::make<CancellationSignal>(self(), generation);
    post([generation, operation, id, token](Session& s) {
        if (generation != s.mGeneration) return;
        if (!s.mInitialized) {
            s.error(fp::Error::HW_UNAVAILABLE);
            return;
        }
        if (s.mPending || s.mOperation != Operation::None) {
            s.error(fp::Error::UNABLE_TO_PROCESS);
            if (!s.mBackend->cancelAndDrain()) fatalBackend();
            return;
        }
        if (operation == Operation::Enroll && !token) {
            s.error(fp::Error::UNABLE_TO_PROCESS);
            return;
        }
        if (operation != Operation::Enroll && s.checkLockout()) return;
        s.mActiveGeneration = generation;
        s.mVendorGeneration = generation;
        s.mOperation = operation;
        if (!s.mUdfps.beginOperation()) {
            s.error(fp::Error::HW_UNAVAILABLE);
            return;
        }
        int rc = 0;
        if (operation == Operation::Enroll) rc = s.mBackend->enroll(*token);
        if (operation == Operation::Authenticate) rc = s.mBackend->authenticate(id);
        if (rc) s.error(fp::Error::UNABLE_TO_PROCESS);
        if (operation == Operation::Enroll && !rc) {
            s.mBackend->executor.postAt(Clock::now() + 600s,
                    [weak = std::weak_ptr<Session>(s.self()), generation] {
                auto session = weak.lock();
                if (!session || session->mClosed ||
                    session->mOperation != Operation::Enroll ||
                    session->mActiveGeneration != generation)
                    return;
                session->error(fp::Error::TIMEOUT);
                if (!session->mBackend->cancelAndDrain()) fatalBackend();
            });
        }
    });
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::enroll(const keymaster::HardwareAuthToken& token,
                                 std::shared_ptr<common::ICancellationSignal>* result) {
    auto converted = toAnc(token);
    return begin(Operation::Enroll, 0, converted, result);
}

ndk::ScopedAStatus Session::authenticate(int64_t id,
                                       std::shared_ptr<common::ICancellationSignal>* result) {
    return begin(Operation::Authenticate, id, std::nullopt, result);
}

ndk::ScopedAStatus Session::detectInteraction(
        std::shared_ptr<common::ICancellationSignal>* result) {
    return begin(Operation::Detect, 0, std::nullopt, result);
}

void Session::cancel(uint64_t generation) {
    if (mClosed || !mGeneration.compare_exchange_strong(generation, generation + 1)) return;
    invalidateTouch();
    post([generation](Session& s) {
        if (s.mActiveGeneration > generation ||
            (s.mActiveGeneration == generation && s.mOperation == Operation::None))
            return;
        if (s.mActiveGeneration == generation) {
            s.finish();
            if (!s.mBackend->cancelAndDrain()) fatalBackend();
        }
        s.mCallback->onError(fp::Error::CANCELED, 0);
    });
}

ndk::ScopedAStatus Session::request(AncEvent::Type expected,
                                   std::function<int(AncBackend&)> call) {
    if (mClosed) return ndk::ScopedAStatus::ok();
    post([expected, call = std::move(call)](Session& s) {
        if (!s.mInitialized) {
            s.error(fp::Error::HW_UNAVAILABLE);
            return;
        }
        if (s.mPending || s.mOperation != Operation::None) {
            s.mCallback->onError(fp::Error::UNABLE_TO_PROCESS, 0);
            return;
        }
        s.mPending = expected;
        uint64_t requestGeneration = ++s.mRequestGeneration;
        int rc = call(*s.mBackend);
        if (rc) {
            s.mPending.reset();
            ++s.mRequestGeneration;
            s.mCallback->onError(fp::Error::UNABLE_TO_PROCESS, 0);
            return;
        }
        s.mBackend->executor.postAt(Clock::now() + 10s,
                [weak = std::weak_ptr<Session>(s.self()), requestGeneration] {
            auto session = weak.lock();
            if (!session || session->mClosed ||
                session->mRequestGeneration != requestGeneration || !session->mPending)
                return;
            session->mPending.reset();
            ++session->mRequestGeneration;
            session->mCallback->onError(fp::Error::TIMEOUT, 0);
        });
    });
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::generateChallenge() {
    return request(AncEvent::Type::ChallengeGenerated, [](AncBackend& b) { return b.generateChallenge(); });
}
ndk::ScopedAStatus Session::revokeChallenge(int64_t challenge) {
    return request(AncEvent::Type::ChallengeRevoked, [challenge](AncBackend& b) {
        return b.revokeChallenge(challenge);
    });
}
ndk::ScopedAStatus Session::enumerateEnrollments() {
    return request(AncEvent::Type::Enumerated, [](AncBackend& b) { return b.enumerate(); });
}
ndk::ScopedAStatus Session::removeEnrollments(const std::vector<int32_t>& ids) {
    if (mClosed) return ndk::ScopedAStatus::ok();
    if (ids.size() > 5 || std::any_of(ids.begin(), ids.end(), [](int32_t id) { return id <= 0; })) {
        post([](Session& s) { s.mCallback->onError(fp::Error::UNABLE_TO_PROCESS, 0); });
        return ndk::ScopedAStatus::ok();
    }
    if (ids.empty()) {
        post([](Session& s) { s.mCallback->onEnrollmentsRemoved({}); });
        return ndk::ScopedAStatus::ok();
    }
    return request(AncEvent::Type::Removed, [ids](AncBackend& b) { return b.remove(ids); });
}
ndk::ScopedAStatus Session::getAuthenticatorId() {
    return request(AncEvent::Type::AuthenticatorId, [](AncBackend& b) { return b.getAuthenticatorId(); });
}
ndk::ScopedAStatus Session::invalidateAuthenticatorId() {
    return request(AncEvent::Type::AuthenticatorIdInvalidated,
                   [](AncBackend& b) { return b.invalidateAuthenticatorId(); });
}

ndk::ScopedAStatus Session::resetLockout(const keymaster::HardwareAuthToken& token) {
    if (mClosed) return ndk::ScopedAStatus::ok();
    auto converted = toAnc(token);
    if (!converted) {
        post([](Session& s) { s.mCallback->onError(fp::Error::UNABLE_TO_PROCESS, 0); });
        return ndk::ScopedAStatus::ok();
    }
    post([token = *converted](Session& s) {
        if (!s.mInitialized || s.mBackend->resetLockout(token)) {
            s.mCallback->onError(fp::Error::UNABLE_TO_PROCESS, 0);
            return;
        }
        auto& state = s.mBackend->lockouts[s.mUserId];
        state.permanent = false;
        state.until = {};
        ++state.generation;
        s.mCallback->onLockoutCleared();
    });
    return ndk::ScopedAStatus::ok();
}

void Session::closeInternal(bool notify) {
    // A replacement session must wait until this cleanup has been queued, even
    // when another binder thread has already marked this session closed.
    std::lock_guard lock(mCloseMutex);
    if (!notify) mRetired = true;
    if (mClosed.exchange(true)) return;
    ++mGeneration;
    invalidateTouch();
    mBackend->executor.post([s = self(), notify] {
        s->finish();
        if (!s->mBackend->cancelAndDrain()) fatalBackend();
        s->mBackend->setListener({});
        // An abandoned callback must not clear framework's replacement session.
        if (notify && !s->mRetired) s->mCallback->onSessionClosed();
    });
}

void Session::retire() { closeInternal(false); }

ndk::ScopedAStatus Session::close() {
    closeInternal(true);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerDown(int32_t id, int32_t x, int32_t y,
                                        float minor, float major) {
    if (mClosed) return ndk::ScopedAStatus::ok();
    if (id < 0 || !std::isfinite(minor) || !std::isfinite(major) || minor < 0 || major < 0 ||
        x < 0 || x >= 1264 || y < 0 || y >= 2780)
        return ndk::ScopedAStatus::ok();
    uint64_t epoch = ++mTouchEpoch;
    post([id, x, y, minor, major, epoch](Session& s) {
        if (epoch != s.mTouchEpoch || s.mIgnoreTouches || s.mDisplayOff ||
            s.mOperation == Operation::None || s.mActiveGeneration != s.mGeneration)
            return;
        if (s.mOperation == Operation::Detect) {
            s.finish();
            s.mCallback->onInteractionDetected();
        } else if (!s.mUdfps.pointerDown(epoch, id, x, y, minor, major)) {
            s.error(fp::Error::HW_UNAVAILABLE);
            if (!s.mBackend->cancelAndDrain()) fatalBackend();
        }
    });
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerUp(int32_t id) {
    if (mClosed || id < 0) return ndk::ScopedAStatus::ok();
    invalidateTouch();
    post([id](Session& s) {
        if (s.mUdfps.hasPointer(id)) s.mUdfps.pointerUp();
    });
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onUiReady() {
    // halControlsIllumination=true: only the panel's TE-confirmed ready is forwarded to ANC.
    return ndk::ScopedAStatus::ok();
}

void Session::updateContext(const common::OperationContext& context) {
    if (mClosed) return;
    bool off = context.displayState == common::DisplayState::NO_UI;
    mDisplayOff = off;
    if (off) {
        invalidateTouch();
        post([](Session& s) { s.mUdfps.pointerUp(); });
    }
}

ndk::ScopedAStatus Session::onContextChanged(const common::OperationContext& context) {
    if (mClosed) return ndk::ScopedAStatus::ok();
    updateContext(context);
    return ndk::ScopedAStatus::ok();
}
ndk::ScopedAStatus Session::authenticateWithContext(int64_t id,
        const common::OperationContext& context, std::shared_ptr<common::ICancellationSignal>* result) {
    updateContext(context);
    return authenticate(id, result);
}
ndk::ScopedAStatus Session::enrollWithContext(const keymaster::HardwareAuthToken& token,
        const common::OperationContext& context, std::shared_ptr<common::ICancellationSignal>* result) {
    updateContext(context);
    return enroll(token, result);
}
ndk::ScopedAStatus Session::detectInteractionWithContext(const common::OperationContext& context,
        std::shared_ptr<common::ICancellationSignal>* result) {
    updateContext(context);
    return detectInteraction(result);
}
ndk::ScopedAStatus Session::onPointerDownWithContext(const fp::PointerContext& context) {
    if (mClosed) return ndk::ScopedAStatus::ok();
    if (!std::isfinite(context.x) || !std::isfinite(context.y) ||
        context.x < 0 || context.x >= 1264 || context.y < 0 || context.y >= 2780)
        return ndk::ScopedAStatus::ok();
    return onPointerDown(context.pointerId, static_cast<int32_t>(context.x),
                         static_cast<int32_t>(context.y),
                         context.minor, context.major);
}
ndk::ScopedAStatus Session::onPointerUpWithContext(const fp::PointerContext& context) {
    return onPointerUp(context.pointerId);
}
ndk::ScopedAStatus Session::onPointerCancelWithContext(const fp::PointerContext&) {
    if (mClosed) return ndk::ScopedAStatus::ok();
    invalidateTouch();
    post([](Session& s) { s.mUdfps.pointerUp(); });
    return ndk::ScopedAStatus::ok();
}
ndk::ScopedAStatus Session::setIgnoreDisplayTouches(bool ignore) {
    if (mClosed) return ndk::ScopedAStatus::ok();
    mIgnoreTouches = ignore;
    if (ignore) {
        invalidateTouch();
        post([](Session& s) { s.mUdfps.pointerUp(); });
    }
    return ndk::ScopedAStatus::ok();
}

void Session::handle(AncEvent event) {
    using Type = AncEvent::Type;
    if (event.type == Type::LockoutTimed || event.type == Type::LockoutPermanent) {
        auto& state = mBackend->lockouts[mUserId];
        state.permanent = event.type == Type::LockoutPermanent;
        // ANC reports seconds; the framework callback and our deadline use milliseconds.
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::seconds(std::min<uint64_t>(event.value, 24 * 60 * 60)));
        state.until = state.permanent ? Clock::time_point{} : Clock::now() + duration;
        uint64_t generation = ++state.generation;
        finish();
        if (state.permanent) {
            mCallback->onLockoutPermanent();
        } else {
            mCallback->onLockoutTimed(duration.count());
            mBackend->executor.postAt(state.until, [weak = std::weak_ptr<Session>(self()), generation] {
                auto s = weak.lock();
                if (!s || s->mClosed) return;
                auto& current = s->mBackend->lockouts[s->mUserId];
                if (current.generation != generation || current.permanent) return;
                current.until = {};
                s->mCallback->onLockoutCleared();
            });
        }
        return;
    }
    if (mPending && event.type == *mPending) {
        mPending.reset();
        ++mRequestGeneration;
        switch (event.type) {
        case Type::ChallengeGenerated: mCallback->onChallengeGenerated(event.value); return;
        case Type::ChallengeRevoked: mCallback->onChallengeRevoked(event.value); return;
        case Type::AuthenticatorId: mCallback->onAuthenticatorIdRetrieved(event.value); return;
        case Type::AuthenticatorIdInvalidated:
            mCallback->onAuthenticatorIdInvalidated(event.value); return;
        case Type::Removed: mCallback->onEnrollmentsRemoved(event.ids); return;
        case Type::Enumerated: mCallback->onEnrollmentsEnumerated(event.ids); return;
        default: break;
        }
    }
    if (event.type == Type::Error && mPending) {
        error(fp::Error::UNABLE_TO_PROCESS);
        return;
    }
    if (mOperation == Operation::None || mActiveGeneration != mGeneration) return;
    switch (event.type) {
    case Type::Acquired:
        if (event.value <= 5) {
            mCallback->onAcquired(static_cast<fp::AcquiredInfo>(event.value + 1), 0);
        } else if (event.value == 6) {
            mCallback->onAcquired(fp::AcquiredInfo::VENDOR, 1);
        } else if (event.value >= 1000 && event.value <= INT32_MAX) {
            mCallback->onAcquired(fp::AcquiredInfo::VENDOR, event.value - 1000);
        } else {
            mCallback->onAcquired(fp::AcquiredInfo::INSUFFICIENT, 0);
        }
        break;
    case Type::Enrollment:
        if (mOperation != Operation::Enroll) return;
        if (!event.remaining) finish();
        mCallback->onEnrollmentProgress(event.id, event.remaining);
        break;
    case Type::Authentication:
        if (mOperation != Operation::Authenticate) return;
        if (event.id) {
            if (event.token.version != 0) {
                error(fp::Error::HW_UNAVAILABLE);
                return;
            }
            finish(true);
            mCallback->onAuthenticationSucceeded(event.id, fromAnc(event.token));
        } else {
            invalidateTouch();
            mUdfps.pointerUp();
            mCallback->onAuthenticationFailed();
        }
        break;
    case Type::Error:
        if (event.value >= 1 && event.value <= 6)
            error(static_cast<fp::Error>(event.value));
        else if (event.value >= 1000 && event.value <= INT32_MAX)
            error(fp::Error::VENDOR, event.value - 1000);
        else
            error(fp::Error::UNABLE_TO_PROCESS);
        break;
    default:
        break;
    }
}

}  // namespace meizu::fingerprint
