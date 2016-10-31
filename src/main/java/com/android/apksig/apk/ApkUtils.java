/*
 * Copyright (C) 2016 The Android Open Source Project
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

package com.android.apksig.apk;

import com.android.apksig.internal.util.Pair;
import com.android.apksig.internal.zip.ZipUtils;
import com.android.apksig.util.DataSource;
import com.android.apksig.zip.ZipFormatException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * APK utilities.
 */
public abstract class ApkUtils {

    private ApkUtils() {}

    /**
     * Finds the main ZIP sections of the provided APK.
     *
     * @throws IOException if an I/O error occurred while reading the APK
     * @throws ZipFormatException if the APK is malformed
     */
    public static ZipSections findZipSections(DataSource apk)
            throws IOException, ZipFormatException {
        Pair<ByteBuffer, Long> eocdAndOffsetInFile =
                ZipUtils.findZipEndOfCentralDirectoryRecord(apk);
        if (eocdAndOffsetInFile == null) {
            throw new ZipFormatException("ZIP End of Central Directory record not found");
        }

        ByteBuffer eocdBuf = eocdAndOffsetInFile.getFirst();
        long eocdOffset = eocdAndOffsetInFile.getSecond();
        eocdBuf.order(ByteOrder.LITTLE_ENDIAN);
        long cdStartOffset = ZipUtils.getZipEocdCentralDirectoryOffset(eocdBuf);
        if (cdStartOffset > eocdOffset) {
            throw new ZipFormatException(
                    "ZIP Central Directory start offset out of range: " + cdStartOffset
                        + ". ZIP End of Central Directory offset: " + eocdOffset);
        }

        long cdSizeBytes = ZipUtils.getZipEocdCentralDirectorySizeBytes(eocdBuf);
        long cdEndOffset = cdStartOffset + cdSizeBytes;
        if (cdEndOffset > eocdOffset) {
            throw new ZipFormatException(
                    "ZIP Central Directory overlaps with End of Central Directory"
                            + ". CD end: " + cdEndOffset
                            + ", EoCD start: " + eocdOffset);
        }

        int cdRecordCount = ZipUtils.getZipEocdCentralDirectoryTotalRecordCount(eocdBuf);

        return new ZipSections(
                cdStartOffset,
                cdSizeBytes,
                cdRecordCount,
                eocdOffset,
                eocdBuf);
    }

    /**
     * Information about the ZIP sections of an APK.
     */
    public static class ZipSections {
        private final long mCentralDirectoryOffset;
        private final long mCentralDirectorySizeBytes;
        private final int mCentralDirectoryRecordCount;
        private final long mEocdOffset;
        private final ByteBuffer mEocd;

        public ZipSections(
                long centralDirectoryOffset,
                long centralDirectorySizeBytes,
                int centralDirectoryRecordCount,
                long eocdOffset,
                ByteBuffer eocd) {
            mCentralDirectoryOffset = centralDirectoryOffset;
            mCentralDirectorySizeBytes = centralDirectorySizeBytes;
            mCentralDirectoryRecordCount = centralDirectoryRecordCount;
            mEocdOffset = eocdOffset;
            mEocd = eocd;
        }

        /**
         * Returns the start offset of the ZIP Central Directory. This value is taken from the
         * ZIP End of Central Directory record.
         */
        public long getZipCentralDirectoryOffset() {
            return mCentralDirectoryOffset;
        }

        /**
         * Returns the size (in bytes) of the ZIP Central Directory. This value is taken from the
         * ZIP End of Central Directory record.
         */
        public long getZipCentralDirectorySizeBytes() {
            return mCentralDirectorySizeBytes;
        }

        /**
         * Returns the number of records in the ZIP Central Directory. This value is taken from the
         * ZIP End of Central Directory record.
         */
        public int getZipCentralDirectoryRecordCount() {
            return mCentralDirectoryRecordCount;
        }

        /**
         * Returns the start offset of the ZIP End of Central Directory record. The record extends
         * until the very end of the APK.
         */
        public long getZipEndOfCentralDirectoryOffset() {
            return mEocdOffset;
        }

        /**
         * Returns the contents of the ZIP End of Central Directory.
         */
        public ByteBuffer getZipEndOfCentralDirectory() {
            return mEocd;
        }
    }

    /**
     * Sets the offset of the start of the ZIP Central Directory in the APK's ZIP End of Central
     * Directory record.
     *
     * @param zipEndOfCentralDirectory APK's ZIP End of Central Directory record
     * @param offset offset of the ZIP Central Directory relative to the start of the archive. Must
     *        be between {@code 0} and {@code 2^32 - 1} inclusive.
     */
    public static void setZipEocdCentralDirectoryOffset(
            ByteBuffer zipEndOfCentralDirectory, long offset) {
        ByteBuffer eocd = zipEndOfCentralDirectory.slice();
        eocd.order(ByteOrder.LITTLE_ENDIAN);
        ZipUtils.setZipEocdCentralDirectoryOffset(eocd, offset);
    }

    /**
     * Name of the Android manifest ZIP entry in APKs.
     */
    private static final String ANDROID_MANIFEST_ZIP_ENTRY_NAME = "AndroidManifest.xml";

    /**
     * Android resource ID of the {@code android:minSdkVersion} attribute in AndroidManifest.xml.
     */
    private static final int MIN_SDK_VERSION_ATTR_ID = 0x0101020c;

    /**
     * Returns the lowest Android platform version (API Level) supported by an APK with the
     * provided {@code AndroidManifest.xml}.
     *
     * @param androidManifestContents contents of {@code AndroidManifest.xml} in binary Android
     *        resource format
     *
     * @throws MinSdkVersionException if an error occurred while determining the API Level
     */
    public static int getMinSdkVersionFromBinaryAndroidManifest(
            ByteBuffer androidManifestContents) throws MinSdkVersionException {
        // IMPLEMENTATION NOTE: Minimum supported Android platform version number is declared using
        // uses-sdk elements which are children of the top-level manifest element. uses-sdk element
        // declares the minimum supported platform version using the android:minSdkVersion attribute
        // whose default value is 1.
        // For each encountered uses-sdk element, the Android runtime checks that its minSdkVersion
        // is not higher than the runtime's API Level and rejects APKs if it is higher. Thus, the
        // effective minSdkVersion value is the maximum over the encountered minSdkVersion values.

        try {
            // If no uses-sdk elements are encountered, Android accepts the APK. We treat this
            // scenario as though the minimum supported API Level is 1.
            int result = 1;

            AndroidBinXmlParser parser = new AndroidBinXmlParser(androidManifestContents);
            int eventType = parser.getEventType();
            while (eventType != AndroidBinXmlParser.EVENT_END_DOCUMENT) {
                if ((eventType == AndroidBinXmlParser.EVENT_START_ELEMENT)
                        && (parser.getDepth() == 2)
                        && ("uses-sdk".equals(parser.getName()))
                        && (parser.getNamespace().isEmpty())) {
                    // In each uses-sdk element, minSdkVersion defaults to 1
                    int minSdkVersion = 1;
                    for (int i = 0; i < parser.getAttributeCount(); i++) {
                        if (parser.getAttributeNameResourceId(i) == MIN_SDK_VERSION_ATTR_ID) {
                            int valueType = parser.getAttributeValueType(i);
                            switch (valueType) {
                                case AndroidBinXmlParser.VALUE_TYPE_INT:
                                    minSdkVersion = parser.getAttributeIntValue(i);
                                    break;
                                case AndroidBinXmlParser.VALUE_TYPE_STRING:
                                {
                                    String codename = parser.getAttributeStringValue(i);
                                    throw new CodenameMinSdkVersionException(
                                            "Unable to determine APK's minimum supported Android"
                                                    + " platform version: Codename in "
                                                    + ANDROID_MANIFEST_ZIP_ENTRY_NAME
                                                    + "'s minSdkVersion" + ": \""
                                                    + codename + "\""
                                                    + ". Only integer values supported.",
                                            codename);
                                }
                                default:
                                    throw new MinSdkVersionException(
                                            "Unable to determine APK's minimum supported Android"
                                                    + ": unsupported value type in "
                                                    + ANDROID_MANIFEST_ZIP_ENTRY_NAME + "'s"
                                                    + " minSdkVersion"
                                                    + ". Only integer values supported.");
                            }
                            break;
                        }
                    }
                    result = Math.max(result, minSdkVersion);
                }
                eventType = parser.next();
            }

            return result;
        } catch (AndroidBinXmlParser.XmlParserException e) {
            throw new MinSdkVersionException(
                    "Unable to determine APK's minimum supported Android platform version"
                            + ": malformed binary resource: " + ANDROID_MANIFEST_ZIP_ENTRY_NAME,
                    e);
        }
    }
}
