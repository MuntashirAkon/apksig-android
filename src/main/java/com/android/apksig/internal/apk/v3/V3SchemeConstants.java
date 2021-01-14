/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.apksig.internal.apk.v3;

/** Constants used by the V3 Signature Scheme signing and verification. */
public class V3SchemeConstants {
    private V3SchemeConstants() {}

    public static final int APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0;
    public static final int PROOF_OF_ROTATION_ATTR_ID = 0x3ba06f8c;
}
