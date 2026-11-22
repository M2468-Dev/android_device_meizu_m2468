// SPDX-License-Identifier: Apache-2.0
#include "UdfpsHandler.h"
#include "Panel.h"

#include <utility>

namespace meizu::fingerprint {

UdfpsHandler::UdfpsHandler(AncBackend& backend)
    : mBackend(backend), mThread([this] { waitForReady(); }) {}

UdfpsHandler::~UdfpsHandler() {
    {
        std::lock_guard lock(mMutex);
        mStopped = true;
    }
    mCondition.notify_all();
    mThread.join();
}

void UdfpsHandler::setReadyCallback(ReadyCallback callback) {
    std::lock_guard lock(mMutex);
    mCallback = std::move(callback);
}

bool UdfpsHandler::beginOperation() {
    std::lock_guard lock(mStateMutex);
    if (!pointerUpLocked() || !Panel::setResult(false)) return false;
    return Panel::setFod(true);
}

void UdfpsHandler::finishOperation(bool authenticated) {
    std::lock_guard lock(mStateMutex);
    // The kernel uses fp_result to choose normal brightness or AOD on exit.
    Panel::setResult(authenticated);
    pointerUpLocked();
    Panel::setFod(false);
}

void UdfpsHandler::invalidateReady() {
    {
        std::lock_guard lock(mMutex);
        ++mEpoch;
        mWaiting = false;
    }
    mCondition.notify_all();
}

bool UdfpsHandler::pointerDown(uint64_t epoch, int32_t pointerId, int32_t x, int32_t y,
                              float minor, float major) {
    std::lock_guard stateLock(mStateMutex);
    if (mPointerId == pointerId) {
        std::lock_guard readyLock(mMutex);
        mEpoch = epoch;
        mWaiting = !mReadySent;
        mCondition.notify_all();
        return true;
    }
    if (!pointerUpLocked() || !Panel::setResult(false)) return false;
    mPointerId = pointerId;
    mReadySent = false;
    mMayBeOn = true;
    // The exported pointer API and command 20013 represent the same ANC event.
    mBackend.pointerDown(pointerId, x, y, minor, major);
    if (!Panel::setHbm(true)) {
        pointerUpLocked();
        return false;
    }
    {
        std::lock_guard lock(mMutex);
        mEpoch = epoch;
        mWaiting = true;
    }
    mCondition.notify_all();
    return true;
}

void UdfpsHandler::pointerUp() {
    std::lock_guard lock(mStateMutex);
    pointerUpLocked();
}

bool UdfpsHandler::pointerUpLocked() {
    bool success = true;
    invalidateReady();
    if (mPointerId >= 0) {
        int32_t id = mPointerId;
        mPointerId = -1;
        mBackend.pointerUp(id);
    }
    if (mMayBeOn) {
        if (Panel::setHbm(false)) mMayBeOn = false;
        else success = false;
    }
    mReadySent = false;
    return success;
}

bool UdfpsHandler::hasPointer(int32_t id) const {
    std::lock_guard lock(mStateMutex);
    return mPointerId == id;
}

UdfpsHandler::ReadyResult UdfpsHandler::deliverReady(uint64_t epoch) {
    std::lock_guard stateLock(mStateMutex);
    {
        std::lock_guard lock(mMutex);
        if (epoch != mEpoch || mReadySent || mPointerId < 0) return ReadyResult::Ignored;
    }
    if (!mBackend.illuminationReady()) {
        pointerUpLocked();
        return ReadyResult::Failed;
    }
    mReadySent = true;
    return ReadyResult::Delivered;
}

void UdfpsHandler::waitForReady() {
    using namespace std::chrono_literals;
    std::unique_lock lock(mMutex);
    while (!mStopped) {
        mCondition.wait(lock, [this] { return mStopped || mWaiting; });
        if (mStopped) return;
        uint64_t epoch = mEpoch;
        auto deadline = std::chrono::steady_clock::now() + 750ms;
        while (mWaiting && mEpoch == epoch && !mStopped) {
            lock.unlock();
            bool ready = Panel::isReady();
            lock.lock();
            if (!mWaiting || mEpoch != epoch || mStopped) break;
            if (ready || std::chrono::steady_clock::now() >= deadline) {
                mWaiting = false;
                auto callback = mCallback;
                lock.unlock();
                if (callback) callback(epoch, ready);
                lock.lock();
                break;
            }
            mCondition.wait_for(lock, 5ms);
        }
    }
}

}  // namespace meizu::fingerprint
