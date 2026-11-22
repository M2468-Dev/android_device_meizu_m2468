// SPDX-License-Identifier: Apache-2.0
#define LOG_TAG "MeizuFingerprint"
#include "Panel.h"

#include <android/log.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace meizu::fingerprint {
namespace {
constexpr char kFod[] = "/sys/devices/platform/main_touch.0/gesture/fod_en";
constexpr char kHbm[] = "/sys/kernel/display_drivers/hbm";
constexpr char kReady[] = "/sys/kernel/display_drivers/hbm_ready_status";
constexpr char kResult[] = "/sys/kernel/display_drivers/fp_result";

bool writeNode(const char* path, char value) {
    int fd;
    do { fd = open(path, O_WRONLY | O_CLOEXEC); } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Open %s: %s", path, strerror(errno));
        return false;
    }
    ssize_t size;
    do { size = write(fd, &value, 1); } while (size < 0 && errno == EINTR);
    int error = errno;
    close(fd);
    if (size == 1) return true;
    __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Write %s=%c: %s", path, value,
                        size < 0 ? strerror(error) : "short write");
    return false;
}
}  // namespace

bool Panel::setFod(bool enabled) { return writeNode(kFod, enabled ? '1' : '0'); }
bool Panel::setHbm(bool enabled) { return writeNode(kHbm, enabled ? '6' : '7'); }
bool Panel::setResult(bool authenticated) { return writeNode(kResult, authenticated ? '1' : '0'); }

bool Panel::isReady() {
    int fd;
    do { fd = open(kReady, O_RDONLY | O_CLOEXEC); } while (fd < 0 && errno == EINTR);
    if (fd < 0) return false;
    char value = 0;
    ssize_t size;
    do { size = read(fd, &value, 1); } while (size < 0 && errno == EINTR);
    close(fd);
    return size == 1 && value == '1';
}

}  // namespace meizu::fingerprint
