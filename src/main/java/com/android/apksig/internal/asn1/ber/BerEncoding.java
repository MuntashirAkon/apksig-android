/*
 * Copyright (C) 2017 The Android Open Source Project
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

package com.android.apksig.internal.asn1.ber;

/**
 * ASN.1 Basic Encoding Rules (BER) constants and helper methods. See {@code X.690}.
 */
public abstract class BerEncoding {
    private BerEncoding() {}

    /**
     * Constructed vs primitive flag in the first identifier byte.
     */
    public static final int ID_FLAG_CONSTRUCTED_ENCODING = 1 << 5;

    /**
     * Tag class: UNIVERSAL
     */
    public static final int TAG_CLASS_UNIVERSAL = 0;

    /**
     * Tag class: APPLICATION
     */
    public static final int TAG_CLASS_APPLICATION = 1;

    /**
     * Tag class: CONTEXT SPECIFIC
     */
    public static final int TAG_CLASS_CONTEXT_SPECIFIC = 2;

    /**
     * Tag class: PRIVATE
     */
    public static final int TAG_CLASS_PRIVATE = 3;

    /**
     * Tag number: INTEGER
     */
    public static final int TAG_NUMBER_INTEGER = 0x2;

    /**
     * Tag number: OCTET STRING
     */
    public static final int TAG_NUMBER_OCTET_STRING = 0x4;

    /**
     * Tag number: NULL
     */
    public static final int TAG_NUMBER_NULL = 0x05;

    /**
     * Tag number: OBJECT IDENTIFIER
     */
    public static final int TAG_NUMBER_OBJECT_IDENTIFIER = 0x6;

    /**
     * Tag number: SEQUENCE
     */
    public static final int TAG_NUMBER_SEQUENCE = 0x10;

    /**
     * Tag number: SET
     */
    public static final int TAG_NUMBER_SET = 0x11;

    public static String tagNumberToString(int tagNumber) {
        switch (tagNumber) {
            case TAG_NUMBER_INTEGER:
                return "INTEGER";
            case TAG_NUMBER_OCTET_STRING:
                return "OCTET STRING";
            case TAG_NUMBER_NULL:
                return "NULL";
            case TAG_NUMBER_OBJECT_IDENTIFIER:
                return "OBJECT IDENTIFIER";
            case TAG_NUMBER_SEQUENCE:
                return "SEQUENCE";
            case TAG_NUMBER_SET:
                return "SET";
            default:
                return "0x" + Integer.toHexString(tagNumber);
        }
    }

    /**
     * Returns {@code true} if the provided first identifier byte indicates that the data value uses
     * constructed encoding for its contents, or {@code false} if the data value uses primitive
     * encoding for its contents.
     */
    public static boolean isConstructed(byte firstIdentifierByte) {
        return (firstIdentifierByte & ID_FLAG_CONSTRUCTED_ENCODING) != 0;
    }

    /**
     * Returns the tag class encoded in the provided first identifier byte. See {@code TAG_CLASS}
     * constants.
     */
    public static int getTagClass(byte firstIdentifierByte) {
        return (firstIdentifierByte & 0xff) >> 6;
    }

    /**
     * Returns the tag number encoded in the provided first identifier byte. See {@code TAG_NUMBER}
     * constants.
     */
    public static int getTagNumber(byte firstIdentifierByte) {
        return firstIdentifierByte & 0x1f;
    }
}

