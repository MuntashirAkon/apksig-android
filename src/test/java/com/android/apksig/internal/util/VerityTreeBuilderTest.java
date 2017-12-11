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

package com.android.apksig.internal.util;

import static java.nio.charset.StandardCharsets.UTF_8;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.fail;

import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;


/** Unit tests for {@link VerityTreeBuilder}. */
@RunWith(JUnit4.class)
public final class VerityTreeBuilderTest {

    @Test public void SHA256RootHashMatch() throws Exception {
        expectRootHash("random-data-4096-bytes", null,
                "a3b013ea0f5d5ffbda26d5e84882faa4c051d592c04b8779bd1f0f4e95cc2657");
        expectRootHash("random-data-4096-bytes", new byte[] { },
                "a3b013ea0f5d5ffbda26d5e84882faa4c051d592c04b8779bd1f0f4e95cc2657");
        expectRootHash("random-data-4096-bytes", new byte[] { 0x00 },
                "cab1bcac3cf9b91151730c0de1880112d2c9865543d3fa56b534273c06667973");
        expectRootHash("random-data-8192-bytes", new byte[] { 0x10 },
                "477afbaa5e884454bb95a8d63366362c21c0a5d7b8e5476b004692bf9a692a00");

        // 524289 requires additional tree level.
        expectRootHash("random-data-524287-bytes", new byte[] { 0x20 },
                "34499b447161546ba412b3a520655b7435718a3fc6ddf7177547885e0ea29892");
        expectRootHash("random-data-524288-bytes", new byte[] { 0x21 },
                "34f8b9c33cd49b753b9341b2d8a4b83e59c5ae458ec6a85fbfebd49314c24d4e");
        expectRootHash("random-data-524289-bytes", new byte[] { 0x22 },
                "2c6b225ddba163fc943b671ba8012a6ba041b9ea76e12b31f484ccebee5506b1");
        expectRootHash("random-data-525000-bytes", new byte[] { 0x23 },
                "b916b0666d749259f0ac5fbb2df54818fc64a2f3a7615e68ade854d0c7ac94f7");
    }

    private static void expectRootHash(String inputResource, byte[] salt, String expectedRootHash)
            throws IOException {
        assertEquals(expectedRootHash, generateRootHash(inputResource, salt));
    }

    private static String generateRootHash(String inputResource, byte[] salt) throws IOException {
        byte[] input = Resources.toByteArray(VerityTreeBuilderTest.class, inputResource);
        assertNotNull(input);
        try {
            VerityTreeBuilder builder = new VerityTreeBuilder(salt);
            return HexEncoding.encode(builder.generateVerityTreeRootHash(
                    DataSources.asDataSource(ByteBuffer.wrap(input))));
        } catch (NoSuchAlgorithmException e) {
            fail(e.getMessage());
            return null;
        }
    }

    private DataSource makeStringDataSource(String data) {
        return DataSources.asDataSource(ByteBuffer.wrap(data.getBytes(UTF_8)));
    }

    @Test public void generateVerityTreeRootHashFromDummyDataSource() throws Exception {
        // This sample was taken from src/test/resources/com/android/apksig/original.apk.
        byte[] sampleEoCDFromDisk = new byte[] {
            0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00, 0x79, 0x01,
            0x00, 0x00, 0x30, 0x16, 0x00, 0x00, 0x00, 0x00
        };
        VerityTreeBuilder builder = new VerityTreeBuilder(null);
        byte[] rootHash = builder.generateVerityTreeRootHash(
                DataSources.asDataSource(ByteBuffer.allocate(4096)),  // before APK Signing Block
                makeStringDataSource("this is central directory (fake data)"),
                DataSources.asDataSource(ByteBuffer.wrap(sampleEoCDFromDisk)));
        assertEquals("7ddb07e6a24ed786ec6edd19cb4f823fb1d657a81ba531e93fe70fdf5b9988ba",
                HexEncoding.encode(rootHash));
    }
}
