// SPDX-License-Identifier: Apache-2.0
#define LOG_TAG "MeizuFingerprint"
#include "Fingerprint.h"
#include "Panel.h"

#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <android/log.h>
#include <string>
#include <utility>

namespace fp = aidl::android::hardware::biometrics::fingerprint;

int main() {
    using namespace meizu::fingerprint;
    auto backend = std::make_shared<AncBackend>();
    if (!backend->open()) return 1;
    auto service = ndk::SharedRefBase::make<Fingerprint>(std::move(backend));
    ABinderProcess_setThreadPoolMaxThreadCount(2);
    std::string instance = std::string(fp::IFingerprint::descriptor) + "/default";
    binder_status_t rc = AServiceManager_addService(service->asBinder().get(), instance.c_str());
    if (rc != STATUS_OK) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Register fingerprint service: %d", rc);
        return 1;
    }
    ABinderProcess_joinThreadPool();
    return 1;
}
