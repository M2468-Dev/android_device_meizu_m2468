#
# Copyright (C) 2026 The Android Open Source Project
#
# SPDX-License-Identifier: Apache-2.0
#

# Inherit from those products. Most specific first.
$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/full_base_telephony.mk)

# Inherit some common Lineage stuff.
$(call inherit-product, vendor/lineage/config/common_full_phone.mk)

# Inherit from m2468 device.
$(call inherit-product, device/meizu/m2468/device.mk)

# Device identifier
PRODUCT_DEVICE := m2468
PRODUCT_NAME := lineage_m2468
PRODUCT_BRAND := meizu
PRODUCT_MODEL := Meizu 21 Note
PRODUCT_MANUFACTURER := meizu

PRODUCT_SYSTEM_NAME := Meizu_21Note_CN
PRODUCT_SYSTEM_DEVICE := Meizu21Note

PRODUCT_BUILD_PROP_OVERRIDES += \
    BuildDesc="qssi-user 16 BQ2A.251110.001-BP2A.250605.031.A3 1764665171 release-keys" \
    BuildFingerprint=meizu/Meizu_21Note_CN/Meizu21Note:16/BQ2A.251016.001-BP2A.250605.031.A3/1764665171:user/release-keys \
    DeviceName=$(PRODUCT_SYSTEM_DEVICE) \
    DeviceProduct=$(PRODUCT_SYSTEM_NAME)

PRODUCT_GMS_CLIENTID_BASE := android-meizu