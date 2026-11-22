// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "AncBackend.h"

#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

namespace meizu::fingerprint {

class UdfpsHandler {
  public:
    enum class ReadyResult { Ignored, Delivered, Failed };
    using ReadyCallback = std::function<void(uint64_t, bool)>;
    explicit UdfpsHandler(AncBackend& backend);
    ~UdfpsHandler();
    void setReadyCallback(ReadyCallback callback);
    bool beginOperation();
    void finishOperation(bool authenticated = false);
    bool pointerDown(uint64_t epoch, int32_t pointerId, int32_t x, int32_t y,
                     float minor, float major);
    void pointerUp();
    void invalidateReady();
    ReadyResult deliverReady(uint64_t epoch);
    bool hasPointer(int32_t id) const;

  private:
    void waitForReady();
    bool pointerUpLocked();
    AncBackend& mBackend;
    mutable std::mutex mStateMutex;
    int32_t mPointerId = -1;
    bool mMayBeOn = false;
    bool mReadySent = false;
    std::mutex mMutex;
    std::condition_variable mCondition;
    uint64_t mEpoch = 0;
    bool mWaiting = false;
    bool mStopped = false;
    ReadyCallback mCallback;
    std::thread mThread;
};

}  // namespace meizu::fingerprint
