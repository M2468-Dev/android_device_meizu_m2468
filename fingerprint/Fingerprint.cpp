// SPDX-License-Identifier: Apache-2.0
#define LOG_TAG "MeizuFingerprint"
#include "Fingerprint.h"

#include <android-base/properties.h>
#include <aidl/android/hardware/biometrics/common/ComponentInfo.h>
#include <android/log.h>
#include <utility>

namespace meizu::fingerprint {

ndk::ScopedAStatus Fingerprint::getSensorProps(std::vector<fp::SensorProps>* result) {
    fp::SensorProps props;
    props.commonProps.sensorId = 0;
    props.commonProps.sensorStrength = common::SensorStrength::STRONG;
    props.commonProps.maxEnrollmentsPerUser = 5;
    common::ComponentInfo sensor;
    sensor.componentId = "fingerprintSensor";
    sensor.hardwareVersion = "Meizu/ANC optical";
    sensor.firmwareVersion = "1";
    sensor.serialNumber = "m2468";
    sensor.softwareVersion = "anc.hal";
    common::ComponentInfo matcher;
    matcher.componentId = "matchingAlgorithm";
    matcher.softwareVersion = "JIIOV";
    props.commonProps.componentInfo = {sensor, matcher};
    props.sensorType = fp::FingerprintSensorType::UNDER_DISPLAY_OPTICAL;
    fp::SensorLocation location;
    location.display = "";
    location.sensorLocationX = android::base::GetIntProperty<int32_t>(
            "vendor.meizu.fingerprint.x", 632);
    location.sensorLocationY = android::base::GetIntProperty<int32_t>(
            "vendor.meizu.fingerprint.y", 2460);
    location.sensorRadius = android::base::GetIntProperty<int32_t>(
            "vendor.meizu.fingerprint.width", 208) / 2;
    props.sensorLocations.push_back(location);
    props.supportsNavigationGestures = false;
    props.supportsDetectInteraction = true;
    props.halHandlesDisplayTouches = false;
    props.halControlsIllumination = true;
    *result = {std::move(props)};
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Fingerprint::createSession(int32_t sensorId, int32_t userId,
        const std::shared_ptr<fp::ISessionCallback>& callback,
        std::shared_ptr<fp::ISession>* result) {
    if (sensorId != 0 || userId < 0 || !callback)
        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
    std::lock_guard lock(mMutex);
    if (mSession) {
        // Framework drops its session after HW_UNAVAILABLE without calling close().
        // Queue retirement before the new session's setActiveGroup on the same executor.
        if (!mSession->isClosed())
            __android_log_print(ANDROID_LOG_WARN, LOG_TAG, "Retiring stale fingerprint session");
        mSession->retire();
    }
    mSession = ndk::SharedRefBase::make<Session>(mBackend, userId, callback);
    mSession->initialize();
    *result = mSession;
    return ndk::ScopedAStatus::ok();
}

}  // namespace meizu::fingerprint
