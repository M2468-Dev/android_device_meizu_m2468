// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>

namespace meizu::fingerprint {

class SerialExecutor {
  public:
    using Clock = std::chrono::steady_clock;
    SerialExecutor();
    ~SerialExecutor();
    void post(std::function<void()> work);
    void postAt(Clock::time_point when, std::function<void()> work);

  private:
    struct Task {
        Clock::time_point when;
        uint64_t sequence;
        std::function<void()> work;
        bool operator<(const Task& other) const {
            return when != other.when ? when > other.when : sequence > other.sequence;
        }
    };
    void run();
    std::mutex mMutex;
    std::condition_variable mCondition;
    std::priority_queue<Task> mTasks;
    uint64_t mSequence = 0;
    bool mStopped = false;
    std::thread mThread;
};

}  // namespace meizu::fingerprint
