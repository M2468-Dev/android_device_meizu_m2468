// SPDX-License-Identifier: Apache-2.0
#include "SerialExecutor.h"

namespace meizu::fingerprint {

SerialExecutor::SerialExecutor() : mThread([this] { run(); }) {}

SerialExecutor::~SerialExecutor() {
    {
        std::lock_guard lock(mMutex);
        mStopped = true;
    }
    mCondition.notify_all();
    mThread.join();
}

void SerialExecutor::post(std::function<void()> work) {
    postAt(Clock::now(), std::move(work));
}

void SerialExecutor::postAt(Clock::time_point when, std::function<void()> work) {
    {
        std::lock_guard lock(mMutex);
        if (mStopped) return;
        mTasks.push({when, ++mSequence, std::move(work)});
    }
    mCondition.notify_one();
}

void SerialExecutor::run() {
    std::unique_lock lock(mMutex);
    while (!mStopped) {
        if (mTasks.empty()) {
            mCondition.wait(lock);
            continue;
        }
        if (mTasks.top().when > Clock::now()) {
            auto deadline = mTasks.top().when;
            mCondition.wait_until(lock, deadline);
            continue;
        }
        auto work = mTasks.top().work;
        mTasks.pop();
        lock.unlock();
        work();
        // Captured sessions can join their ready worker during destruction.
        // Release them before taking the queue lock that worker uses to post.
        work = {};
        lock.lock();
    }
}

}  // namespace meizu::fingerprint
