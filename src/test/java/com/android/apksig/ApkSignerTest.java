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

package com.android.apksig;

import static com.android.apksig.apk.ApkUtils.SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME;
import static com.android.apksig.apk.ApkUtils.findZipSections;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.android.apksig.ApkVerifier.Issue;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.SignatureInfo;
import com.android.apksig.internal.apk.stamp.SourceStampConstants;
import com.android.apksig.internal.apk.v1.V1SchemeVerifier;
import com.android.apksig.internal.apk.v2.V2SchemeConstants;
import com.android.apksig.internal.apk.v3.V3SchemeConstants;
import com.android.apksig.internal.asn1.Asn1BerParser;
import com.android.apksig.internal.util.AndroidSdkVersion;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.internal.util.Resources;
import com.android.apksig.internal.x509.RSAPublicKey;
import com.android.apksig.internal.x509.SubjectPublicKeyInfo;
import com.android.apksig.internal.zip.CentralDirectoryRecord;
import com.android.apksig.internal.zip.LocalFileRecord;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksig.zip.ZipFormatException;

import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.HashSet;
import java.util.Set;

@RunWith(JUnit4.class)
public class ApkSignerTest {

    /**
     * Whether to preserve, as files, outputs of failed tests. This is useful for investigating test
     * failures.
     */
    private static final boolean KEEP_FAILING_OUTPUT_AS_FILES = false;

    // All signers with the same prefix and an _X suffix were signed with the private key of the
    // (X-1) signer.
    private static final String FIRST_RSA_2048_SIGNER_RESOURCE_NAME = "rsa-2048";
    private static final String SECOND_RSA_2048_SIGNER_RESOURCE_NAME = "rsa-2048_2";
    private static final String THIRD_RSA_2048_SIGNER_RESOURCE_NAME = "rsa-2048_3";

    private static final String EC_P256_SIGNER_RESOURCE_NAME = "ec-p256";

    // This is the same cert as above with the modulus reencoded to remove the leading 0 sign bit.
    private static final String FIRST_RSA_2048_SIGNER_CERT_WITH_NEGATIVE_MODULUS =
            "rsa-2048_negmod.x509.der";

    private static final String LINEAGE_RSA_2048_2_SIGNERS_RESOURCE_NAME =
            "rsa-2048-lineage-2-signers";

    // These are the ID and value of an extra signature block within the APK signing block that
    // can be preserved through the setOtherSignersSignaturesPreserved API.
    private final int EXTRA_BLOCK_ID = 0x7e57c0de;
    private final byte[] EXTRA_BLOCK_VALUE = {0, 1, 2, 3, 4, 5, 6, 7};

    @Rule
    public TemporaryFolder mTemporaryFolder = new TemporaryFolder();

    public static void main(String[] params) throws Exception {
        File outDir = (params.length > 0) ? new File(params[0]) : new File(".");
        generateGoldenFiles(outDir);
    }

    private static void generateGoldenFiles(File outDir) throws Exception {
        System.out.println(
                "Generating golden files "
                        + ApkSignerTest.class.getSimpleName()
                        + " into "
                        + outDir);
        if (!outDir.exists()) {
            if (!outDir.mkdirs()) {
                throw new IOException("Failed to create directory: " + outDir);
            }
        }
        List<ApkSigner.SignerConfig> rsa2048SignerConfig =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        List<ApkSigner.SignerConfig> rsa2048SignerConfigWithLineage =
                Arrays.asList(
                        rsa2048SignerConfig.get(0),
                        getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME));
        SigningCertificateLineage lineage =
                Resources.toSigningCertificateLineage(
                        ApkSignerTest.class, LINEAGE_RSA_2048_2_SIGNERS_RESOURCE_NAME);

        signGolden(
                "golden-unaligned-in.apk",
                new File(outDir, "golden-unaligned-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig));
        signGolden(
                "golden-legacy-aligned-in.apk",
                new File(outDir, "golden-legacy-aligned-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig));
        signGolden(
                "golden-aligned-in.apk",
                new File(outDir, "golden-aligned-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig));

        signGolden(
                "golden-unaligned-in.apk",
                new File(outDir, "golden-unaligned-v1-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(false)
                        .setV4SigningEnabled(false));
        signGolden(
                "golden-legacy-aligned-in.apk",
                new File(outDir, "golden-legacy-aligned-v1-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(false)
                        .setV4SigningEnabled(false));
        signGolden(
                "golden-aligned-in.apk",
                new File(outDir, "golden-aligned-v1-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(false)
                        .setV4SigningEnabled(false));

        signGolden(
                "golden-unaligned-in.apk",
                new File(outDir, "golden-unaligned-v2-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false));
        signGolden(
                "golden-legacy-aligned-in.apk",
                new File(outDir, "golden-legacy-aligned-v2-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false));
        signGolden(
                "golden-aligned-in.apk",
                new File(outDir, "golden-aligned-v2-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false));

        signGolden(
                "golden-unaligned-in.apk",
                new File(outDir, "golden-unaligned-v3-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true));
        signGolden(
                "golden-legacy-aligned-in.apk",
                new File(outDir, "golden-legacy-aligned-v3-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true));
        signGolden(
                "golden-aligned-in.apk",
                new File(outDir, "golden-aligned-v3-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true));

        signGolden(
                "golden-unaligned-in.apk",
                new File(outDir, "golden-unaligned-v3-lineage-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
        signGolden(
                "golden-legacy-aligned-in.apk",
                new File(outDir, "golden-legacy-aligned-v3-lineage-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
        signGolden(
                "golden-aligned-in.apk",
                new File(outDir, "golden-aligned-v3-lineage-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));

        signGolden(
                "golden-unaligned-in.apk",
                new File(outDir, "golden-unaligned-v1v2-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false));
        signGolden(
                "golden-legacy-aligned-in.apk",
                new File(outDir, "golden-legacy-aligned-v1v2-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false));
        signGolden(
                "golden-aligned-in.apk",
                new File(outDir, "golden-aligned-v1v2-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false));

        signGolden(
                "golden-unaligned-in.apk",
                new File(outDir, "golden-unaligned-v2v3-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));
        signGolden(
                "golden-legacy-aligned-in.apk",
                new File(outDir, "golden-legacy-aligned-v2v3-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));
        signGolden(
                "golden-aligned-in.apk",
                new File(outDir, "golden-aligned-v2v3-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));
        signGolden(
                "golden-unaligned-in.apk",
                new File(outDir, "golden-unaligned-v2v3-lineage-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
        signGolden(
                "golden-legacy-aligned-in.apk",
                new File(outDir, "golden-legacy-aligned-v2v3-lineage-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
        signGolden(
                "golden-aligned-in.apk",
                new File(outDir, "golden-aligned-v2v3-lineage-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));

        signGolden(
                "golden-unaligned-in.apk",
                new File(outDir, "golden-unaligned-v1v2v3-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));
        signGolden(
                "golden-legacy-aligned-in.apk",
                new File(outDir, "golden-legacy-aligned-v1v2v3-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));
        signGolden(
                "golden-aligned-in.apk",
                new File(outDir, "golden-aligned-v1v2v3-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));
        signGolden(
                "golden-unaligned-in.apk",
                new File(outDir, "golden-unaligned-v1v2v3-lineage-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
        signGolden(
                "golden-legacy-aligned-in.apk",
                new File(outDir, "golden-legacy-aligned-v1v2v3-lineage-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
        signGolden(
                "golden-aligned-in.apk",
                new File(outDir, "golden-aligned-v1v2v3-lineage-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));

        signGolden(
                "original.apk",
                new File(outDir, "golden-rsa-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig));
        signGolden(
                "original.apk",
                new File(outDir, "golden-rsa-minSdkVersion-1-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig).setMinSdkVersion(1));
        signGolden(
                "original.apk",
                new File(outDir, "golden-rsa-minSdkVersion-18-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig).setMinSdkVersion(18));
        signGolden(
                "original.apk",
                new File(outDir, "golden-rsa-minSdkVersion-24-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig).setMinSdkVersion(24));
        signGolden(
                "original.apk",
                new File(outDir, "golden-rsa-verity-out.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setVerityEnabled(true));
        signGolden(
                "original.apk",
                new File(outDir, "golden-file-size-aligned.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setAlignFileSize(true));
        signGolden(
                "pinsapp-unsigned.apk",
                new File(outDir, "golden-pinsapp-signed.apk"),
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setVerityEnabled(true));
    }

    private static void signGolden(
            String inResourceName, File outFile, ApkSigner.Builder apkSignerBuilder)
            throws Exception {
        DataSource in =
                DataSources.asDataSource(
                        ByteBuffer.wrap(Resources.toByteArray(ApkSigner.class, inResourceName)));
        apkSignerBuilder.setInputApk(in).setOutputApk(outFile);

        File outFileIdSig = new File(outFile.getCanonicalPath() + ".idsig");
        apkSignerBuilder.setV4SignatureOutputFile(outFileIdSig);
        apkSignerBuilder.setV4ErrorReportingEnabled(true);

        apkSignerBuilder.build().sign();
    }

    @Test
    public void testAlignmentPreserved_Golden() throws Exception {
        // Regression tests for preserving (mis)alignment of ZIP Local File Header data
        // NOTE: Expected output files can be re-generated by running the "main" method.

        List<ApkSigner.SignerConfig> rsa2048SignerConfig =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        List<ApkSigner.SignerConfig> rsa2048SignerConfigWithLineage =
                Arrays.asList(
                        rsa2048SignerConfig.get(0),
                        getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME));
        SigningCertificateLineage lineage =
                Resources.toSigningCertificateLineage(
                        getClass(), LINEAGE_RSA_2048_2_SIGNERS_RESOURCE_NAME);
        // Uncompressed entries in this input file are not aligned -- the file was created using
        // the jar utility. temp4.txt entry was then manually added into the archive. This entry's
        // ZIP Local File Header "extra" field declares that the entry's data must be aligned to
        // 4 kB boundary, but the data isn't actually aligned in the file.
        assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig));
        assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v1-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(false)
                        .setV4SigningEnabled(false));
        assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v2-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false));
        assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v3-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true));
        assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v3-lineage-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
        assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v1v2-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false));
        assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v2v3-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));
        assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v2v3-lineage-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
        assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v1v2v3-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));
        assertGolden(
                "golden-unaligned-in.apk",
                "golden-unaligned-v1v2v3-lineage-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));

        // Uncompressed entries in this input file are aligned by zero-padding the "extra" field, as
        // performed by zipalign at the time of writing. This padding technique produces ZIP
        // archives whose "extra" field are not compliant with APPNOTE.TXT. Hence, this technique
        // was deprecated.
        assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig));
        assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v1-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(false)
                        .setV4SigningEnabled(false));
        assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v2-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false));
        assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v3-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true));
        assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v3-lineage-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
        assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v1v2-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false));
        assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v2v3-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));
        assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v2v3-lineage-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
        assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v1v2v3-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));
        assertGolden(
                "golden-legacy-aligned-in.apk",
                "golden-legacy-aligned-v1v2v3-lineage-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));

        // Uncompressed entries in this input file are aligned by padding the "extra" field, as
        // generated by signapk and apksigner. This padding technique produces "extra" fields which
        // are compliant with APPNOTE.TXT.
        assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig));
        assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v1-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(false)
                        .setV4SigningEnabled(false));
        assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v2-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false));
        assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v3-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true));
        assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v3-lineage-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
        assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v1v2-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false));
        assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v2v3-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));
        assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v2v3-lineage-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
        assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v1v2v3-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true));
        assertGolden(
                "golden-aligned-in.apk",
                "golden-aligned-v1v2v3-lineage-out.apk",
                new ApkSigner.Builder(rsa2048SignerConfigWithLineage)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
    }

    @Test
    public void testMinSdkVersion_Golden() throws Exception {
        // Regression tests for minSdkVersion-based signature/digest algorithm selection
        // NOTE: Expected output files can be re-generated by running the "main" method.

        List<ApkSigner.SignerConfig> rsaSignerConfig =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        assertGolden("original.apk", "golden-rsa-out.apk", new ApkSigner.Builder(rsaSignerConfig));
        assertGolden(
                "original.apk",
                "golden-rsa-minSdkVersion-1-out.apk",
                new ApkSigner.Builder(rsaSignerConfig).setMinSdkVersion(1));
        assertGolden(
                "original.apk",
                "golden-rsa-minSdkVersion-18-out.apk",
                new ApkSigner.Builder(rsaSignerConfig).setMinSdkVersion(18));
        assertGolden(
                "original.apk",
                "golden-rsa-minSdkVersion-24-out.apk",
                new ApkSigner.Builder(rsaSignerConfig).setMinSdkVersion(24));

        // TODO: Add tests for DSA and ECDSA. This is non-trivial because the default
        // implementations of these signature algorithms are non-deterministic which means output
        // files always differ from golden files.
    }

    @Test
    public void testVerityEnabled_Golden() throws Exception {
        List<ApkSigner.SignerConfig> rsaSignerConfig =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));

        assertGolden(
                "original.apk",
                "golden-rsa-verity-out.apk",
                new ApkSigner.Builder(rsaSignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setVerityEnabled(true));
    }

    @Test
    public void testAlignFileSize_Golden() throws Exception {
        List<ApkSigner.SignerConfig> rsaSignerConfig =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        String goldenOutput = "golden-file-size-aligned.apk";
        assertGolden(
                "original.apk",
                goldenOutput,
                new ApkSigner.Builder(rsaSignerConfig).setAlignFileSize(true));
        assertTrue(Resources.toByteArray(getClass(), goldenOutput).length % 4096 == 0);
    }

    @Test
    public void testRsaSignedVerifies() throws Exception {
        List<ApkSigner.SignerConfig> signers =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        String in = "original.apk";

        // Sign so that the APK is guaranteed to verify on API Level 1+
        File out = sign(in, new ApkSigner.Builder(signers).setMinSdkVersion(1));
        assertVerified(verifyForMinSdkVersion(out, 1));

        // Sign so that the APK is guaranteed to verify on API Level 18+
        out = sign(in, new ApkSigner.Builder(signers).setMinSdkVersion(18));
        assertVerified(verifyForMinSdkVersion(out, 18));
        // Does not verify on API Level 17 because RSA with SHA-256 not supported
        assertVerificationFailure(
                verifyForMinSdkVersion(out, 17), Issue.JAR_SIG_UNSUPPORTED_SIG_ALG);
    }

    @Test
    public void testDsaSignedVerifies() throws Exception {
        List<ApkSigner.SignerConfig> signers =
                Collections.singletonList(getDefaultSignerConfigFromResources("dsa-1024"));
        String in = "original.apk";

        // Sign so that the APK is guaranteed to verify on API Level 1+
        File out = sign(in, new ApkSigner.Builder(signers).setMinSdkVersion(1));
        assertVerified(verifyForMinSdkVersion(out, 1));

        // Sign so that the APK is guaranteed to verify on API Level 21+
        out = sign(in, new ApkSigner.Builder(signers).setMinSdkVersion(21));
        assertVerified(verifyForMinSdkVersion(out, 21));
        // Does not verify on API Level 20 because DSA with SHA-256 not supported
        assertVerificationFailure(
                verifyForMinSdkVersion(out, 20), Issue.JAR_SIG_UNSUPPORTED_SIG_ALG);
    }


    @Test
    public void testDeterministicDsaSignedVerifies() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        try {
            List<ApkSigner.SignerConfig> signers =
                    Collections.singletonList(getDeterministicDsaSignerConfigFromResources("dsa-2048"));
            String in = "original.apk";

            // Sign so that the APK is guaranteed to verify on API Level 1+
            File out = sign(in, new ApkSigner.Builder(signers).setMinSdkVersion(1));
            assertVerified(verifyForMinSdkVersion(out, 1));

            // Sign so that the APK is guaranteed to verify on API Level 21+
            out = sign(in, new ApkSigner.Builder(signers).setMinSdkVersion(21));
            assertVerified(verifyForMinSdkVersion(out, 21));
            // Does not verify on API Level 20 because DSA with SHA-256 not supported
            assertVerificationFailure(
                    verifyForMinSdkVersion(out, 20), Issue.JAR_SIG_UNSUPPORTED_SIG_ALG);
        } finally {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    @Test
    public void testDeterministicDsaSigningIsDeterministic() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        try {
            List<ApkSigner.SignerConfig> signers =
                    Collections.singletonList(getDeterministicDsaSignerConfigFromResources("dsa-2048"));
            String in = "original.apk";

            ApkSigner.Builder apkSignerBuilder = new ApkSigner.Builder(signers).setMinSdkVersion(1);
            File first = sign(in, apkSignerBuilder);
            File second = sign(in, apkSignerBuilder);

            assertFileContentsEqual(first, second);
        } finally {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    @Test
    public void testEcSignedVerifies() throws Exception {
        List<ApkSigner.SignerConfig> signers =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(EC_P256_SIGNER_RESOURCE_NAME));
        String in = "original.apk";

        // NOTE: EC APK signatures are not supported prior to API Level 18
        // Sign so that the APK is guaranteed to verify on API Level 18+
        File out = sign(in, new ApkSigner.Builder(signers).setMinSdkVersion(18));
        assertVerified(verifyForMinSdkVersion(out, 18));
        // Does not verify on API Level 17 because EC not supported
        assertVerificationFailure(
                verifyForMinSdkVersion(out, 17), Issue.JAR_SIG_UNSUPPORTED_SIG_ALG);
    }

    @Test
    public void testV1SigningRejectsInvalidZipEntryNames() throws Exception {
        // ZIP/JAR entry name cannot contain CR, LF, or NUL characters when the APK is being
        // JAR-signed.
        List<ApkSigner.SignerConfig> signers =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));

        assertThrows(
                ApkFormatException.class,
                () ->
                        sign(
                                "v1-only-with-cr-in-entry-name.apk",
                                new ApkSigner.Builder(signers).setV1SigningEnabled(true)));
        assertThrows(
                ApkFormatException.class,
                () ->
                        sign(
                                "v1-only-with-lf-in-entry-name.apk",
                                new ApkSigner.Builder(signers).setV1SigningEnabled(true)));
        assertThrows(
                ApkFormatException.class,
                () ->
                        sign(
                                "v1-only-with-nul-in-entry-name.apk",
                                new ApkSigner.Builder(signers).setV1SigningEnabled(true)));
    }

    @Test
    public void testWeirdZipCompressionMethod() throws Exception {
        // Any ZIP compression method other than STORED is treated as DEFLATED by Android.
        // This APK declares compression method 21 (neither STORED nor DEFLATED) for CERT.RSA entry,
        // but the entry is actually Deflate-compressed.
        List<ApkSigner.SignerConfig> signers =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        sign("weird-compression-method.apk", new ApkSigner.Builder(signers));
    }

    @Test
    public void testZipCompressionMethodMismatchBetweenLfhAndCd() throws Exception {
        // Android Package Manager ignores compressionMethod field in Local File Header and always
        // uses the compressionMethod from Central Directory instead.
        // In this APK, compression method of CERT.RSA is declared as STORED in Local File Header
        // and as DEFLATED in Central Directory. The entry is actually Deflate-compressed.
        List<ApkSigner.SignerConfig> signers =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        sign("mismatched-compression-method.apk", new ApkSigner.Builder(signers));
    }

    @Test
    public void testDebuggableApk() throws Exception {
        // APK which uses a boolean value "true" in its android:debuggable
        final String debuggableBooleanApk = "debuggable-boolean.apk";
        List<ApkSigner.SignerConfig> signers =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        // Signing debuggable APKs is permitted by default
        sign(debuggableBooleanApk, new ApkSigner.Builder(signers));
        // Signing debuggable APK succeeds when explicitly requested
        sign(debuggableBooleanApk, new ApkSigner.Builder(signers).setDebuggableApkPermitted(true));

        // Signing debuggable APK fails when requested
        assertThrows(
                SignatureException.class,
                () ->
                        sign(
                                debuggableBooleanApk,
                                new ApkSigner.Builder(signers).setDebuggableApkPermitted(false)));

        // APK which uses a reference value, pointing to boolean "false", in its android:debuggable
        final String debuggableResourceApk = "debuggable-resource.apk";
        // When we permit signing regardless of whether the APK is debuggable, the value of
        // android:debuggable should be ignored.
        sign(debuggableResourceApk, new ApkSigner.Builder(signers).setDebuggableApkPermitted(true));

        // When we disallow signing debuggable APKs, APKs with android:debuggable being a resource
        // reference must be rejected, because there's no easy way to establish whether the resolved
        // boolean value is the same for all resource configurations.
        assertThrows(
                SignatureException.class,
                () ->
                        sign(
                                debuggableResourceApk,
                                new ApkSigner.Builder(signers).setDebuggableApkPermitted(false)));
    }

    @Test
    public void testV3SigningWithSignersNotInLineageFails() throws Exception {
        // APKs signed with the v3 scheme after a key rotation must specify the lineage containing
        // the proof of rotation. This test verifies that the signing will fail if the provided
        // signers are not in the specified lineage.
        List<ApkSigner.SignerConfig> signers =
                Arrays.asList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME),
                        getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME));
        SigningCertificateLineage lineage =
                Resources.toSigningCertificateLineage(getClass(), "rsa-1024-lineage-2-signers");
        assertThrows(
                IllegalStateException.class,
                () ->
                        sign(
                                "original.apk",
                                new ApkSigner.Builder(signers)
                                        .setSigningCertificateLineage(lineage)));
    }

    @Test
    public void testSigningWithLineageRequiresOldestSignerForV1AndV2() throws Exception {
        // After a key rotation the oldest signer must still be specified for v1 and v2 signing.
        // The lineage contains the proof of rotation and will be used to determine the oldest
        // signer.
        ApkSigner.SignerConfig firstSigner =
                getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
        ApkSigner.SignerConfig secondSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
        ApkSigner.SignerConfig thirdSigner =
                getDefaultSignerConfigFromResources(THIRD_RSA_2048_SIGNER_RESOURCE_NAME);
        SigningCertificateLineage lineage =
                Resources.toSigningCertificateLineage(getClass(), "rsa-2048-lineage-3-signers");

        // Verifies that the v1 signing scheme requires the oldest signer after a key rotation.
        List<ApkSigner.SignerConfig> signers = Collections.singletonList(thirdSigner);
        try {
            sign(
                    "original.apk",
                    new ApkSigner.Builder(signers)
                            .setV1SigningEnabled(true)
                            .setV2SigningEnabled(false)
                            .setV3SigningEnabled(true)
                            .setSigningCertificateLineage(lineage));
            fail(
                    "The signing should have failed due to the oldest signer in the lineage not"
                            + " being provided for v1 signing");
        } catch (IllegalArgumentException expected) {
        }

        // Verifies that the v2 signing scheme requires the oldest signer after a key rotation.
        try {
            sign(
                    "original.apk",
                    new ApkSigner.Builder(signers)
                            .setV1SigningEnabled(false)
                            .setV2SigningEnabled(true)
                            .setV3SigningEnabled(true)
                            .setSigningCertificateLineage(lineage));
            fail(
                    "The signing should have failed due to the oldest signer in the lineage not"
                            + " being provided for v2 signing");
        } catch (IllegalArgumentException expected) {
        }

        // Verifies that when only the v3 signing scheme is requested the oldest signer does not
        // need to be provided.
        sign(
                "original.apk",
                new ApkSigner.Builder(signers)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));

        // Verifies that an intermediate signer in the lineage is not sufficient to satisfy the
        // requirement that the oldest signer be provided for v1 and v2 signing.
        signers = Arrays.asList(secondSigner, thirdSigner);
        try {
            sign(
                    "original.apk",
                    new ApkSigner.Builder(signers)
                            .setV1SigningEnabled(true)
                            .setV2SigningEnabled(true)
                            .setV3SigningEnabled(true)
                            .setSigningCertificateLineage(lineage));
            fail(
                    "The signing should have failed due to the oldest signer in the lineage not"
                            + " being provided for v1/v2 signing");
        } catch (IllegalArgumentException expected) {
        }

        // Verifies that the signing is successful when the oldest and newest signers are provided
        // and that intermediate signers are not required.
        signers = Arrays.asList(firstSigner, thirdSigner);
        sign(
                "original.apk",
                new ApkSigner.Builder(signers)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setSigningCertificateLineage(lineage));
    }

    @Test
    public void testV3SigningWithMultipleSignersAndNoLineageFails() throws Exception {
        // The v3 signing scheme does not support multiple signers; if multiple signers are provided
        // it is assumed these signers are part of the lineage. This test verifies v3 signing
        // fails if multiple signers are provided without a lineage.
        ApkSigner.SignerConfig firstSigner =
                getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
        ApkSigner.SignerConfig secondSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
        List<ApkSigner.SignerConfig> signers = Arrays.asList(firstSigner, secondSigner);
        assertThrows(
                IllegalStateException.class,
                () ->
                        sign(
                                "original.apk",
                                new ApkSigner.Builder(signers)
                                        .setV1SigningEnabled(true)
                                        .setV2SigningEnabled(true)
                                        .setV3SigningEnabled(true)));
    }

    @Test
    public void testLineageCanBeReadAfterV3Signing() throws Exception {
        SigningCertificateLineage.SignerConfig firstSigner =
                Resources.toLineageSignerConfig(getClass(), FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
        SigningCertificateLineage.SignerConfig secondSigner =
                Resources.toLineageSignerConfig(getClass(), SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
        SigningCertificateLineage lineage =
                new SigningCertificateLineage.Builder(firstSigner, secondSigner).build();
        List<ApkSigner.SignerConfig> signerConfigs =
                Arrays.asList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME),
                        getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME));
        File out =
                sign(
                        "original.apk",
                        new ApkSigner.Builder(signerConfigs)
                                .setV3SigningEnabled(true)
                                .setSigningCertificateLineage(lineage));
        SigningCertificateLineage lineageFromApk = SigningCertificateLineage.readFromApkFile(out);
        assertTrue(
                "The first signer was not in the lineage from the signed APK",
                lineageFromApk.isSignerInLineage((firstSigner)));
        assertTrue(
                "The second signer was not in the lineage from the signed APK",
                lineageFromApk.isSignerInLineage((secondSigner)));
    }

    @Test
    public void testPublicKeyHasPositiveModulusAfterSigning() throws Exception {
        // The V2 and V3 signature schemes include the public key from the certificate in the
        // signing block. If a certificate with an RSAPublicKey is improperly encoded with a
        // negative modulus this was previously written to the signing block as is and failed on
        // device verification since on device the public key in the certificate was reencoded with
        // the correct encoding for the modulus. This test uses an improperly encoded certificate to
        // sign an APK and verifies that the public key in the signing block is corrected with a
        // positive modulus to allow on device installs / updates.
        List<ApkSigner.SignerConfig> signersList =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(
                                FIRST_RSA_2048_SIGNER_RESOURCE_NAME,
                                FIRST_RSA_2048_SIGNER_CERT_WITH_NEGATIVE_MODULUS));
        File signedApk =
                sign(
                        "original.apk",
                        new ApkSigner.Builder(signersList)
                                .setV1SigningEnabled(true)
                                .setV2SigningEnabled(true)
                                .setV3SigningEnabled(true));
        RSAPublicKey v2PublicKey =
                getRSAPublicKeyFromSigningBlock(
                        signedApk, ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2);
        assertTrue(
                "The modulus in the public key in the V2 signing block must not be negative",
                v2PublicKey.modulus.compareTo(BigInteger.ZERO) > 0);
        RSAPublicKey v3PublicKey =
                getRSAPublicKeyFromSigningBlock(
                        signedApk, ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3);
        assertTrue(
                "The modulus in the public key in the V3 signing block must not be negative",
                v3PublicKey.modulus.compareTo(BigInteger.ZERO) > 0);
    }

    @Test
    public void testV4State_disableV2V3EnableV4_fails() throws Exception {
        ApkSigner.SignerConfig signer =
                getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);

        assertThrows(
                IllegalStateException.class,
                () ->
                        sign(
                                "original.apk",
                                new ApkSigner.Builder(Collections.singletonList(signer))
                                        .setV1SigningEnabled(true)
                                        .setV2SigningEnabled(false)
                                        .setV3SigningEnabled(false)
                                        .setV4SigningEnabled(true)));
    }

    @Test
    public void testSignApk_stampFile() throws Exception {
        List<ApkSigner.SignerConfig> signers =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(sourceStampSigner.getCertificates().get(0).getEncoded());
        byte[] expectedStampCertificateDigest = messageDigest.digest();

        File signedApkFile =
                sign(
                        "original.apk",
                        new ApkSigner.Builder(signers)
                                .setV1SigningEnabled(true)
                                .setSourceStampSignerConfig(sourceStampSigner));

        try (RandomAccessFile f = new RandomAccessFile(signedApkFile, "r")) {
            DataSource signedApk = DataSources.asDataSource(f, 0, f.length());

            ApkUtils.ZipSections zipSections = findZipSections(signedApk);
            List<CentralDirectoryRecord> cdRecords =
                    V1SchemeVerifier.parseZipCentralDirectory(signedApk, zipSections);
            CentralDirectoryRecord stampCdRecord = null;
            for (CentralDirectoryRecord cdRecord : cdRecords) {
                if (SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME.equals(cdRecord.getName())) {
                    stampCdRecord = cdRecord;
                    break;
                }
            }
            assertNotNull(stampCdRecord);
            byte[] actualStampCertificateDigest =
                    LocalFileRecord.getUncompressedData(
                            signedApk, stampCdRecord, zipSections.getZipCentralDirectoryOffset());
            assertArrayEquals(expectedStampCertificateDigest, actualStampCertificateDigest);
        }
    }

    @Test
    public void testSignApk_existingStampFile_sameSourceStamp() throws Exception {
        List<ApkSigner.SignerConfig> signers =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME);

        File signedApk =
                sign(
                        "original-with-stamp-file.apk",
                        new ApkSigner.Builder(signers)
                                .setV1SigningEnabled(true)
                                .setV2SigningEnabled(true)
                                .setV3SigningEnabled(true)
                                .setSourceStampSignerConfig(sourceStampSigner));

        ApkVerifier.Result sourceStampVerificationResult =
                verify(signedApk, /* minSdkVersionOverride= */ null);
        assertSourceStampVerified(signedApk, sourceStampVerificationResult);
    }

    @Test
    public void testSignApk_existingStampFile_differentSourceStamp() throws Exception {
        List<ApkSigner.SignerConfig> signers =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);

        Exception exception =
                assertThrows(
                        ApkFormatException.class,
                        () ->
                                sign(
                                        "original-with-stamp-file.apk",
                                        new ApkSigner.Builder(signers)
                                                .setV1SigningEnabled(true)
                                                .setV2SigningEnabled(true)
                                                .setV3SigningEnabled(true)
                                                .setSourceStampSignerConfig(sourceStampSigner)));
        assertEquals(
                String.format(
                        "Cannot generate SourceStamp. APK contains an existing entry with the"
                                + " name: %s, and it is different than the provided source stamp"
                                + " certificate",
                        SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME),
                exception.getMessage());
    }

    @Test
    public void testSignApk_existingStampFile_differentSourceStamp_forceOverwrite()
            throws Exception {
        List<ApkSigner.SignerConfig> signers =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);

        File signedApk =
                sign(
                        "original-with-stamp-file.apk",
                        new ApkSigner.Builder(signers)
                                .setV1SigningEnabled(true)
                                .setV2SigningEnabled(true)
                                .setV3SigningEnabled(true)
                                .setForceSourceStampOverwrite(true)
                                .setSourceStampSignerConfig(sourceStampSigner));

        ApkVerifier.Result sourceStampVerificationResult =
                verify(signedApk, /* minSdkVersionOverride= */ null);
        assertSourceStampVerified(signedApk, sourceStampVerificationResult);
    }

    @Test
    public void testSignApk_stampBlock_noStampGenerated() throws Exception {
        List<ApkSigner.SignerConfig> signersList =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));

        File signedApkFile =
                sign(
                        "original.apk",
                        new ApkSigner.Builder(signersList)
                                .setV1SigningEnabled(true)
                                .setV2SigningEnabled(true)
                                .setV3SigningEnabled(true));

        try (RandomAccessFile f = new RandomAccessFile(signedApkFile, "r")) {
            DataSource signedApk = DataSources.asDataSource(f, 0, f.length());

            ApkUtils.ZipSections zipSections = ApkUtils.findZipSections(signedApk);
            ApkSigningBlockUtils.Result result =
                    new ApkSigningBlockUtils.Result(ApkSigningBlockUtils.VERSION_SOURCE_STAMP);
            assertThrows(
                    ApkSigningBlockUtils.SignatureNotFoundException.class,
                    () ->
                            ApkSigningBlockUtils.findSignature(
                                    signedApk,
                                    zipSections,
                                    ApkSigningBlockUtils.VERSION_SOURCE_STAMP,
                                    result));
        }
    }

    @Test
    public void testSignApk_stampBlock_whenV1SignaturePresent() throws Exception {
        List<ApkSigner.SignerConfig> signersList =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);

        File signedApk =
                sign(
                        "original.apk",
                        new ApkSigner.Builder(signersList)
                                .setV1SigningEnabled(true)
                                .setV2SigningEnabled(false)
                                .setV3SigningEnabled(false)
                                .setV4SigningEnabled(false)
                                .setSourceStampSignerConfig(sourceStampSigner));

        ApkVerifier.Result sourceStampVerificationResult =
                verify(signedApk, /* minSdkVersionOverride= */ null);
        assertSourceStampVerified(signedApk, sourceStampVerificationResult);
    }

    @Test
    public void testSignApk_stampBlock_whenV2SignaturePresent() throws Exception {
        List<ApkSigner.SignerConfig> signersList =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);

        File signedApk =
                sign(
                        "original.apk",
                        new ApkSigner.Builder(signersList)
                                .setV1SigningEnabled(false)
                                .setV2SigningEnabled(true)
                                .setV3SigningEnabled(false)
                                .setSourceStampSignerConfig(sourceStampSigner));

        ApkVerifier.Result sourceStampVerificationResult =
                verifyForMinSdkVersion(signedApk, /* minSdkVersion= */ AndroidSdkVersion.N);
        assertSourceStampVerified(signedApk, sourceStampVerificationResult);
    }

    @Test
    public void testSignApk_stampBlock_whenV3SignaturePresent() throws Exception {
        List<ApkSigner.SignerConfig> signersList =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);

        File signedApk =
                sign(
                        "original.apk",
                        new ApkSigner.Builder(signersList)
                                .setV1SigningEnabled(false)
                                .setV2SigningEnabled(false)
                                .setV3SigningEnabled(true)
                                .setSourceStampSignerConfig(sourceStampSigner));

        ApkVerifier.Result sourceStampVerificationResult =
                verifyForMinSdkVersion(signedApk, /* minSdkVersion= */ AndroidSdkVersion.N);
        assertSourceStampVerified(signedApk, sourceStampVerificationResult);
    }

    @Test
    public void testSignApk_stampBlock_withStampLineage() throws Exception {
        List<ApkSigner.SignerConfig> signersList =
                Collections.singletonList(
                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        ApkSigner.SignerConfig sourceStampSigner =
                getDefaultSignerConfigFromResources(SECOND_RSA_2048_SIGNER_RESOURCE_NAME);
        SigningCertificateLineage sourceStampLineage =
                Resources.toSigningCertificateLineage(
                        getClass(), LINEAGE_RSA_2048_2_SIGNERS_RESOURCE_NAME);

        File signedApk =
                sign(
                        "original.apk",
                        new ApkSigner.Builder(signersList)
                                .setV1SigningEnabled(true)
                                .setV2SigningEnabled(true)
                                .setV3SigningEnabled(true)
                                .setSourceStampSignerConfig(sourceStampSigner)
                                .setSourceStampSigningCertificateLineage(sourceStampLineage));

        ApkVerifier.Result sourceStampVerificationResult =
                verify(signedApk, /* minSdkVersion= */ null);
        assertSourceStampVerified(signedApk, sourceStampVerificationResult);
    }

    @Test
    public void testSignApk_Pinlist() throws Exception {
        List<ApkSigner.SignerConfig> rsa2048SignerConfig =
            Collections.singletonList(
                getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        assertGolden(
            "pinsapp-unsigned.apk",
            "golden-pinsapp-signed.apk",
            new ApkSigner.Builder(rsa2048SignerConfig)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .setVerityEnabled(true));
        assertTrue("pinlist.meta file must be in the signed APK.",
            resourceZipFileContains("golden-pinsapp-signed.apk", "pinlist.meta"));
    }

    @Test
    public void testOtherSignersSignaturesPreserved_extraSigBlock_signatureAppended()
            throws Exception {
        // The DefaultApkSignerEngine contains support to append a signature to an existing
        // signing block; any existing signature blocks within the APK signing block should be
        // left intact except for the original verity padding block (since this is regenerated) and
        // the source stamp. This test verifies that an extra signature block is still in
        // the APK signing block after appending a V2 signature.
        List<ApkSigner.SignerConfig> ecP256SignerConfig = Collections.singletonList(
                getDefaultSignerConfigFromResources(EC_P256_SIGNER_RESOURCE_NAME));

        File signedApk = sign("v2-rsa-2048-with-extra-sig-block.apk",
                new ApkSigner.Builder(ecP256SignerConfig)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(false)
                .setV4SigningEnabled(false)
                .setOtherSignersSignaturesPreserved(true));

        ApkVerifier.Result result = verify(signedApk, null);
        assertVerified(result);
        assertResultContainsSigners(result, FIRST_RSA_2048_SIGNER_RESOURCE_NAME,
                EC_P256_SIGNER_RESOURCE_NAME);
        assertSigningBlockContains(signedApk, Pair.of(EXTRA_BLOCK_VALUE, EXTRA_BLOCK_ID));
    }

    @Test
    public void testOtherSignersSignaturesPreserved_v1Only_signatureAppended() throws Exception {
        // This test verifies appending an additional V1 signature to an existing V1 signer behaves
        // similar to jarsigner where the APK is then verified as signed by both signers.
        List<ApkSigner.SignerConfig> ecP256SignerConfig = Collections.singletonList(
                getDefaultSignerConfigFromResources(EC_P256_SIGNER_RESOURCE_NAME));

        File signedApk = sign("v1-only-with-rsa-2048.apk",
                new ApkSigner.Builder(ecP256SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(false)
                        .setV3SigningEnabled(false)
                        .setV4SigningEnabled(false)
                        .setOtherSignersSignaturesPreserved(true));

        ApkVerifier.Result result = verify(signedApk, null);
        assertVerified(result);
        assertResultContainsSigners(result, FIRST_RSA_2048_SIGNER_RESOURCE_NAME,
                EC_P256_SIGNER_RESOURCE_NAME);
    }

    @Test
    public void testOtherSignersSignaturesPreserved_v3OnlyDifferentSigner_throwsException()
            throws Exception {
        // The V3 Signature Scheme only supports a single signer; if an attempt is made to append
        // a different signer to a V3 signature then an exception should be thrown.
        // The APK used for this test is signed with the ec-p256 signer so use the rsa-2048 to
        // attempt to append a different signature.
        List<ApkSigner.SignerConfig> rsa2048SignerConfig = Collections.singletonList(
                getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));

        assertThrows(IllegalStateException.class, () ->
                sign("v3-only-with-stamp.apk",
                    new ApkSigner.Builder(rsa2048SignerConfig)
                            .setV1SigningEnabled(false)
                            .setV2SigningEnabled(false)
                            .setV3SigningEnabled(true)
                            .setV4SigningEnabled(false)
                            .setOtherSignersSignaturesPreserved(true))
        );
    }

    @Test
    public void testOtherSignersSignaturesPreserved_v2OnlyAppendV2V3SameSigner_signatureAppended()
          throws Exception {
        // A V2 and V3 signature can be appended to an existing V2 signature if the same signer is
        // used to resign the APK; this could be used in a case where an APK was previously signed
        // with just the V2 signature scheme along with additional non-APK signing scheme signature
        // blocks and the signer wanted to preserve those existing blocks.
        List<ApkSigner.SignerConfig> rsa2048SignerConfig = Collections.singletonList(
                getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));

        File signedApk = sign("v2-rsa-2048-with-extra-sig-block.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(true)
                        .setV4SigningEnabled(false)
                        .setOtherSignersSignaturesPreserved(true));

        ApkVerifier.Result result = verify(signedApk, null);
        assertVerified(result);
        assertResultContainsSigners(result, FIRST_RSA_2048_SIGNER_RESOURCE_NAME);
        assertSigningBlockContains(signedApk, Pair.of(EXTRA_BLOCK_VALUE, EXTRA_BLOCK_ID));
    }

    @Test
    public void testOtherSignersSignaturesPreserved_v2OnlyAppendV3SameSigner_throwsException()
            throws Exception {
        // A V3 only signature cannot be appended to an existing V2 signature, even when using the
        // same signer, since the V2 signature would then not contain the stripping protection for
        // the V3 signature. If the same signer is being used then the signer should be configured
        // to resign using the V2 signature scheme as well as the V3 signature scheme.
        List<ApkSigner.SignerConfig> rsa2048SignerConfig = Collections.singletonList(
                getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));

        assertThrows(IllegalStateException.class, () ->
                sign("v2-rsa-2048-with-extra-sig-block.apk",
                    new ApkSigner.Builder(rsa2048SignerConfig)
                            .setV1SigningEnabled(false)
                            .setV2SigningEnabled(false)
                            .setV3SigningEnabled(true)
                            .setV4SigningEnabled(false)
                            .setOtherSignersSignaturesPreserved(true)));
    }

    @Test
    public void testOtherSignersSignaturesPreserved_v1v2IndividuallySign_signaturesAppended()
            throws Exception {
        // One of the primary requirements for appending signatures is when an APK has already
        // released with two signers; with the minimum signature scheme v2 requirement for target
        // SDK version 30+ each signer must be able to append their signature to the existing
        // signature block. This test verifies an APK with appended signatures verifies as expected
        // after a series of appending V1 and V2 signatures.
        List<ApkSigner.SignerConfig> rsa2048SignerConfig = Collections.singletonList(
                getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
        List<ApkSigner.SignerConfig> ecP256SignerConfig = Collections.singletonList(
                getDefaultSignerConfigFromResources(EC_P256_SIGNER_RESOURCE_NAME));

        // When two parties are signing an APK the first must sign with both V1 and V2; this will
        // write the stripping-protection attribute to the V1 signature.
        File signedApk = sign("original.apk",
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false)
                        .setV4SigningEnabled(false));

        // The second party can then append their signature with both the V1 and V2 signature; this
        // will invalidate the V2 signature of the initial signer since the APK itself will be
        // modified with this signers V1 / jar signature.
        signedApk = sign(signedApk,
                new ApkSigner.Builder(ecP256SignerConfig)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false)
                        .setV4SigningEnabled(false)
                        .setOtherSignersSignaturesPreserved(true));

        // The first party will then need to resign with just the V2 signature after its previous
        // signature was invalidated by the V1 signature of the second signer; however since this
        // signature is appended its previous V2 signature should be removed from the signature
        // block and replaced with this new signature while preserving the V2 signature of the
        // other signer.
        signedApk = sign(signedApk,
                new ApkSigner.Builder(rsa2048SignerConfig)
                        .setV1SigningEnabled(false)
                        .setV2SigningEnabled(true)
                        .setV3SigningEnabled(false)
                        .setV4SigningEnabled(false)
                        .setOtherSignersSignaturesPreserved(true));

        ApkVerifier.Result result = verify(signedApk, null);
        assertVerified(result);
        assertResultContainsSigners(result, FIRST_RSA_2048_SIGNER_RESOURCE_NAME,
                EC_P256_SIGNER_RESOURCE_NAME);
    }

    /**
     * Asserts the provided {@code signedApk} contains a signature block with the expected
     * {@code byte[]} value and block ID as specified in the {@code expectedBlock}.
     */
    private static void assertSigningBlockContains(File signedApk,
            Pair<byte[], Integer> expectedBlock) throws Exception {
        try (RandomAccessFile apkFile = new RandomAccessFile(signedApk, "r")) {
            ApkUtils.ApkSigningBlock apkSigningBlock = ApkUtils.findApkSigningBlock(
                    DataSources.asDataSource(apkFile));
            List<Pair<byte[], Integer>> signatureBlocks =
                    ApkSigningBlockUtils.getApkSignatureBlocks(apkSigningBlock.getContents());
            for (Pair<byte[], Integer> signatureBlock : signatureBlocks) {
                if (signatureBlock.getSecond().equals(expectedBlock.getSecond())) {
                    if (Arrays.equals(signatureBlock.getFirst(), expectedBlock.getFirst())) {
                        return;
                    }
                }
            }
            fail(String.format(
                    "The APK signing block did not contain the expected block with ID %08x",
                    expectedBlock.getSecond()));
        }
    }

    /**
     * Asserts the provided verification {@code result} contains the expected {@code signers} for
     * each scheme that was used to verify the APK's signature.
     */
    private static void assertResultContainsSigners(ApkVerifier.Result result, String... signers)
            throws Exception {
        // A result must be successfully verified before verifying any of the result's signers.
        assertTrue(result.isVerified());

        List<X509Certificate> expectedSigners = new ArrayList<>();
        for (String signer : signers) {
            ApkSigner.SignerConfig signerConfig = getDefaultSignerConfigFromResources(signer);
            expectedSigners.addAll(signerConfig.getCertificates());
        }

        if (result.isVerifiedUsingV1Scheme()) {
            Set<X509Certificate> v1Signers = new HashSet<>();
            for (ApkVerifier.Result.V1SchemeSignerInfo signer : result.getV1SchemeSigners()) {
                v1Signers.add(signer.getCertificate());
            }
            assertEquals(expectedSigners.size(), v1Signers.size());
            assertTrue("Expected V1 signers: " + getAllSubjectNamesFrom(expectedSigners)
                            + ", actual V1 signers: " + getAllSubjectNamesFrom(v1Signers),
                    v1Signers.containsAll(expectedSigners));
        }

        if (result.isVerifiedUsingV2Scheme()) {
            Set<X509Certificate> v2Signers = new HashSet<>();
            for (ApkVerifier.Result.V2SchemeSignerInfo signer : result.getV2SchemeSigners()) {
                v2Signers.add(signer.getCertificate());
            }
            assertEquals(expectedSigners.size(), v2Signers.size());
            assertTrue("Expected V2 signers: " + getAllSubjectNamesFrom(expectedSigners)
                            + ", actual V2 signers: " + getAllSubjectNamesFrom(v2Signers),
                    v2Signers.containsAll(expectedSigners));
        }

        if (result.isVerifiedUsingV3Scheme()) {
            Set<X509Certificate> v3Signers = new HashSet<>();
            for (ApkVerifier.Result.V3SchemeSignerInfo signer : result.getV3SchemeSigners()) {
                v3Signers.add(signer.getCertificate());
            }
            assertEquals(expectedSigners.size(), v3Signers.size());
            assertTrue("Expected V3 signers: " + getAllSubjectNamesFrom(expectedSigners)
                            + ", actual V3 signers: " + getAllSubjectNamesFrom(v3Signers),
                    v3Signers.containsAll(expectedSigners));
        }
    }

    /**
     * Returns a comma delimited {@code String} containing all of the Subject Names from the
     * provided {@code certificates}.
     */
    private static String getAllSubjectNamesFrom(Collection<X509Certificate> certificates) {
        StringBuilder result = new StringBuilder();
        for (X509Certificate certificate : certificates) {
            if (result.length() > 0) {
                result.append(", ");
            }
            result.append(certificate.getSubjectDN().getName());
        }
        return result.toString();
    }

    private static boolean resourceZipFileContains(String resourceName, String zipEntryName)
        throws IOException {
        ZipInputStream zip = new ZipInputStream(
            Resources.toInputStream(ApkSignerTest.class, resourceName));
        while (true) {
            ZipEntry entry = zip.getNextEntry();
            if (entry == null) {
                break;
            }

            if (entry.getName().equals(zipEntryName)) {
                return true;
            }
        }

        return false;
    }

    private RSAPublicKey getRSAPublicKeyFromSigningBlock(File apk, int signatureVersionId)
            throws Exception {
        int signatureVersionBlockId;
        switch (signatureVersionId) {
            case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V2:
                signatureVersionBlockId = V2SchemeConstants.APK_SIGNATURE_SCHEME_V2_BLOCK_ID;
                break;
            case ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3:
                signatureVersionBlockId = V3SchemeConstants.APK_SIGNATURE_SCHEME_V3_BLOCK_ID;
                break;
            default:
                throw new Exception(
                        "Invalid signature version ID specified: " + signatureVersionId);
        }
        SignatureInfo signatureInfo =
                getSignatureInfoFromApk(apk, signatureVersionId, signatureVersionBlockId);
        // FORMAT:
        // * length prefixed sequence of length prefixed signers
        //   * length-prefixed signed data
        //   * V3+ only - minSDK (uint32)
        //   * V3+ only - maxSDK (uint32)
        //   * length-prefixed sequence of length-prefixed signatures:
        //   * length-prefixed bytes: public key (X.509 SubjectPublicKeyInfo, ASN.1 DER encoded)
        ByteBuffer signers =
                ApkSigningBlockUtils.getLengthPrefixedSlice(signatureInfo.signatureBlock);
        ByteBuffer signer = ApkSigningBlockUtils.getLengthPrefixedSlice(signers);
        // Since all the data is read from the signer block the signedData and signatures are
        // discarded.
        ApkSigningBlockUtils.getLengthPrefixedSlice(signer);
        // For V3+ signature version IDs discard the min / max SDKs as well
        if (signatureVersionId >= ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V3) {
            signer.getInt();
            signer.getInt();
        }
        ApkSigningBlockUtils.getLengthPrefixedSlice(signer);
        ByteBuffer publicKey = ApkSigningBlockUtils.getLengthPrefixedSlice(signer);
        SubjectPublicKeyInfo subjectPublicKeyInfo =
                Asn1BerParser.parse(publicKey, SubjectPublicKeyInfo.class);
        ByteBuffer subjectPublicKeyBuffer = subjectPublicKeyInfo.subjectPublicKey;
        // The SubjectPublicKey is stored as a bit string in the SubjectPublicKeyInfo with the first
        // byte indicating the number of padding bits in the public key. Read this first byte to
        // allow parsing the rest of the RSAPublicKey as a sequence.
        subjectPublicKeyBuffer.get();
        return Asn1BerParser.parse(subjectPublicKeyBuffer, RSAPublicKey.class);
    }

    private static SignatureInfo getSignatureInfoFromApk(
            File apkFile, int signatureVersionId, int signatureVersionBlockId)
            throws IOException, ZipFormatException,
            ApkSigningBlockUtils.SignatureNotFoundException {
        try (RandomAccessFile f = new RandomAccessFile(apkFile, "r")) {
            DataSource apk = DataSources.asDataSource(f, 0, f.length());
            ApkUtils.ZipSections zipSections = ApkUtils.findZipSections(apk);
            ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(
                    signatureVersionId);
            return ApkSigningBlockUtils.findSignature(apk, zipSections, signatureVersionBlockId,
                    result);
        }
    }

    /**
     * Asserts that signing the specified golden input file using the provided signing configuration
     * produces output identical to the specified golden output file.
     */
    private void assertGolden(
            String inResourceName,
            String expectedOutResourceName,
            ApkSigner.Builder apkSignerBuilder)
            throws Exception {
        // Sign the provided golden input
        File out = sign(inResourceName, apkSignerBuilder);
        assertVerified(verify(out, AndroidSdkVersion.P));

        // Assert that the output is identical to the provided golden output
        if (out.length() > Integer.MAX_VALUE) {
            throw new RuntimeException("Output too large: " + out.length() + " bytes");
        }
        byte[] outData = new byte[(int) out.length()];
        try (FileInputStream fis = new FileInputStream(out)) {
            fis.read(outData);
        }
        ByteBuffer actualOutBuf = ByteBuffer.wrap(outData);

        ByteBuffer expectedOutBuf =
                ByteBuffer.wrap(Resources.toByteArray(getClass(), expectedOutResourceName));

        boolean identical = false;
        if (actualOutBuf.remaining() == expectedOutBuf.remaining()) {
            while (actualOutBuf.hasRemaining()) {
                if (actualOutBuf.get() != expectedOutBuf.get()) {
                    break;
                }
            }
            identical = !actualOutBuf.hasRemaining();
        }

        if (identical) {
            return;
        }

        if (KEEP_FAILING_OUTPUT_AS_FILES) {
            File tmp = File.createTempFile(getClass().getSimpleName(), ".apk");
            Files.copy(out.toPath(), tmp.toPath());
            fail(tmp + " differs from " + expectedOutResourceName);
        } else {
            fail("Output differs from " + expectedOutResourceName);
        }
    }

    private File sign(File inApkFile, ApkSigner.Builder apkSignerBuilder) throws Exception {
        try (RandomAccessFile apkFile = new RandomAccessFile(inApkFile, "r")) {
            DataSource in = DataSources.asDataSource(apkFile);
            return sign(in, apkSignerBuilder);
        }
    }

    private File sign(String inResourceName, ApkSigner.Builder apkSignerBuilder) throws Exception {
        DataSource in =
                DataSources.asDataSource(
                        ByteBuffer.wrap(Resources.toByteArray(getClass(), inResourceName)));
        return sign(in, apkSignerBuilder);
    }

    private File sign(DataSource in, ApkSigner.Builder apkSignerBuilder) throws Exception {
        File outFile = mTemporaryFolder.newFile();
        apkSignerBuilder.setInputApk(in).setOutputApk(outFile);

        File outFileIdSig = new File(outFile.getCanonicalPath() + ".idsig");
        apkSignerBuilder.setV4SignatureOutputFile(outFileIdSig);
        apkSignerBuilder.setV4ErrorReportingEnabled(true);

        apkSignerBuilder.build().sign();
        return outFile;
    }

    private static ApkVerifier.Result verifyForMinSdkVersion(File apk, int minSdkVersion)
            throws IOException, ApkFormatException, NoSuchAlgorithmException {
        return verify(apk, minSdkVersion);
    }

    private static ApkVerifier.Result verify(File apk, Integer minSdkVersionOverride)
            throws IOException, ApkFormatException, NoSuchAlgorithmException {
        ApkVerifier.Builder builder = new ApkVerifier.Builder(apk);
        if (minSdkVersionOverride != null) {
            builder.setMinCheckedPlatformVersion(minSdkVersionOverride);
        }
        File idSig = new File(apk.getCanonicalPath() + ".idsig");
        if (idSig.exists()) {
            builder.setV4SignatureFile(idSig);
        }
        return builder.build().verify();
    }

    private static void assertVerified(ApkVerifier.Result result) {
        ApkVerifierTest.assertVerified(result);
    }

    private static void assertSourceStampVerified(File signedApk, ApkVerifier.Result result)
            throws ApkSigningBlockUtils.SignatureNotFoundException, IOException,
            ZipFormatException {
        SignatureInfo signatureInfo =
                getSignatureInfoFromApk(
                        signedApk,
                        ApkSigningBlockUtils.VERSION_SOURCE_STAMP,
                        SourceStampConstants.V2_SOURCE_STAMP_BLOCK_ID);
        assertNotNull(signatureInfo.signatureBlock);
        assertTrue(result.isSourceStampVerified());
    }

    private static void assertVerificationFailure(ApkVerifier.Result result, Issue expectedIssue) {
        ApkVerifierTest.assertVerificationFailure(result, expectedIssue);
    }

    private void assertFileContentsEqual(File first, File second) throws IOException {
        assertArrayEquals(Files.readAllBytes(Paths.get(first.getPath())),
                Files.readAllBytes(Paths.get(second.getPath())));
    }

    private static ApkSigner.SignerConfig getDefaultSignerConfigFromResources(
            String keyNameInResources) throws Exception {
        return getDefaultSignerConfigFromResources(keyNameInResources, false);
    }

    private static ApkSigner.SignerConfig getDefaultSignerConfigFromResources(
            String keyNameInResources, boolean deterministicDsaSigning) throws Exception {
        PrivateKey privateKey =
                Resources.toPrivateKey(ApkSignerTest.class, keyNameInResources + ".pk8");
        List<X509Certificate> certs =
                Resources.toCertificateChain(ApkSignerTest.class, keyNameInResources + ".x509.pem");
        return new ApkSigner.SignerConfig.Builder(keyNameInResources, privateKey, certs,
                deterministicDsaSigning).build();
    }

    private static ApkSigner.SignerConfig getDefaultSignerConfigFromResources(
            String keyNameInResources, String certNameInResources) throws Exception {
        PrivateKey privateKey =
                Resources.toPrivateKey(ApkSignerTest.class, keyNameInResources + ".pk8");
        List<X509Certificate> certs =
                Resources.toCertificateChain(ApkSignerTest.class, certNameInResources);
        return new ApkSigner.SignerConfig.Builder(keyNameInResources, privateKey, certs).build();
    }

    private static ApkSigner.SignerConfig getDeterministicDsaSignerConfigFromResources(
            String keyNameInResources) throws Exception {
        return getDefaultSignerConfigFromResources(keyNameInResources, true);
    }
}
