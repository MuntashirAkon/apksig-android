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

package com.android.apksig;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeNoException;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.internal.util.AndroidSdkVersion;
import com.android.apksig.internal.util.HexEncoding;
import com.android.apksig.internal.util.Resources;
import com.android.apksig.util.DataSources;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RunWith(JUnit4.class)
public class SourceStampVerifierTest {
    private static final String RSA_2048_CERT_SHA256_DIGEST =
            "fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8";
    private static final String EC_P256_CERT_SHA256_DIGEST =
            "6a8b96e278e58f62cfe3584022cec1d0527fcb85a9e5d2e1694eb0405be5b599";

    @Test
    public void verifySourceStamp_correctSignature() throws Exception {
        SourceStampVerifier.Result verificationResult = verifySourceStamp("valid-stamp.apk");
        // Since the API is only verifying the source stamp the result itself should be marked as
        // verified.
        assertVerified(verificationResult);

        // The source stamp can also be verified by platform version; confirm the verification works
        // using just the max signature scheme version supported by that platform version.
        verificationResult = verifySourceStamp("valid-stamp.apk", 18, 18);
        assertVerified(verificationResult);

        verificationResult = verifySourceStamp("valid-stamp.apk", 24, 24);
        assertVerified(verificationResult);

        verificationResult = verifySourceStamp("valid-stamp.apk", 28, 28);
        assertVerified(verificationResult);
    }

    @Test
    public void verifySourceStamp_signatureMissing() throws Exception {
        SourceStampVerifier.Result verificationResult = verifySourceStamp(
                "stamp-without-block.apk");
        assertSourceStampVerificationFailure(verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_SIG_MISSING);
    }

    @Test
    public void verifySourceStamp_certificateMismatch() throws Exception {
        SourceStampVerifier.Result verificationResult = verifySourceStamp(
                "stamp-certificate-mismatch.apk");
        assertSourceStampVerificationFailure(
                verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK);
    }

    @Test
    public void verifySourceStamp_v1OnlySignatureValidStamp() throws Exception {
        SourceStampVerifier.Result verificationResult = verifySourceStamp("v1-only-with-stamp.apk");
        assertVerified(verificationResult);

        // Confirm that the source stamp verification succeeds when specifying platform versions
        // that supported later signature scheme versions.
        verificationResult = verifySourceStamp("v1-only-with-stamp.apk", 28, 28);
        assertVerified(verificationResult);

        verificationResult = verifySourceStamp("v1-only-with-stamp.apk", 24, 24);
        assertVerified(verificationResult);
    }

    @Test
    public void verifySourceStamp_v2OnlySignatureValidStamp() throws Exception {
        // The SourceStampVerifier will not query the APK's manifest for the minSdkVersion, so
        // set the min / max versions to prevent failure due to a missing V1 signature.
        SourceStampVerifier.Result verificationResult = verifySourceStamp("v2-only-with-stamp.apk",
                24, 24);
        assertVerified(verificationResult);

        // Confirm that the source stamp verification succeeds when specifying a platform version
        // that supports a later signature scheme version.
        verificationResult = verifySourceStamp("v2-only-with-stamp.apk", 28, 28);
        assertVerified(verificationResult);
    }

    @Test
    public void verifySourceStamp_v3OnlySignatureValidStamp() throws Exception {
        // The SourceStampVerifier will not query the APK's manifest for the minSdkVersion, so
        // set the min / max versions to prevent failure due to a missing V1 signature.
        SourceStampVerifier.Result verificationResult = verifySourceStamp("v3-only-with-stamp.apk",
                28, 28);
        assertVerified(verificationResult);
    }

    @Test
    public void verifySourceStamp_apkHashMismatch_v1SignatureScheme() throws Exception {
        SourceStampVerifier.Result verificationResult = verifySourceStamp(
                "stamp-apk-hash-mismatch-v1.apk");
        assertSourceStampVerificationFailure(verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_DID_NOT_VERIFY);
    }

    @Test
    public void verifySourceStamp_apkHashMismatch_v2SignatureScheme() throws Exception {
        SourceStampVerifier.Result verificationResult = verifySourceStamp(
                "stamp-apk-hash-mismatch-v2.apk");
        assertSourceStampVerificationFailure(verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_DID_NOT_VERIFY);
    }

    @Test
    public void verifySourceStamp_apkHashMismatch_v3SignatureScheme() throws Exception {
        SourceStampVerifier.Result verificationResult = verifySourceStamp(
                "stamp-apk-hash-mismatch-v3.apk");
        assertSourceStampVerificationFailure(verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_DID_NOT_VERIFY);
    }

    @Test
    public void verifySourceStamp_malformedSignature() throws Exception {
        SourceStampVerifier.Result verificationResult = verifySourceStamp(
                "stamp-malformed-signature.apk");
        assertSourceStampVerificationFailure(
                verificationResult, ApkVerificationIssue.SOURCE_STAMP_MALFORMED_SIGNATURE);
    }

    @Test
    public void verifySourceStamp_expectedDigestMatchesActual() throws Exception {
        // The ApkVerifier provides an API to specify the expected certificate digest; this test
        // verifies that the test runs through to completion when the actual digest matches the
        // provided value.
        SourceStampVerifier.Result verificationResult = verifySourceStamp("v3-only-with-stamp.apk",
                RSA_2048_CERT_SHA256_DIGEST, 28, 28);
        assertVerified(verificationResult);
    }

    @Test
    public void verifySourceStamp_expectedDigestMismatch() throws Exception {
        // If the caller requests source stamp verification with an expected cert digest that does
        // not match the actual digest in the APK the verifier should report the mismatch.
        SourceStampVerifier.Result verificationResult = verifySourceStamp("v3-only-with-stamp.apk",
                EC_P256_CERT_SHA256_DIGEST);
        assertSourceStampVerificationFailure(verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH);
    }

    @Test
    public void verifySourceStamp_noStampCertDigestNorSignatureBlock() throws Exception {
        // The caller of this API expects that the provided APK should be signed with a source
        // stamp; if no artifacts of the stamp are present ensure that the API fails indicating the
        // missing stamp.
        SourceStampVerifier.Result verificationResult = verifySourceStamp("original.apk");
        assertSourceStampVerificationFailure(verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING);
    }

    private SourceStampVerifier.Result verifySourceStamp(String apkFilenameInResources)
            throws Exception {
        return verifySourceStamp(apkFilenameInResources, null, null, null);
    }

    private SourceStampVerifier.Result verifySourceStamp(String apkFilenameInResources,
            String expectedCertDigest) throws Exception {
        return verifySourceStamp(apkFilenameInResources, expectedCertDigest, null, null);
    }

    private SourceStampVerifier.Result verifySourceStamp(String apkFilenameInResources,
            Integer minSdkVersionOverride, Integer maxSdkVersionOverride) throws Exception {
        return verifySourceStamp(apkFilenameInResources, null, minSdkVersionOverride,
                maxSdkVersionOverride);
    }

    private SourceStampVerifier.Result verifySourceStamp(String apkFilenameInResources,
            String expectedCertDigest, Integer minSdkVersionOverride, Integer maxSdkVersionOverride)
            throws Exception {
        byte[] apkBytes = Resources.toByteArray(getClass(), apkFilenameInResources);
        SourceStampVerifier.Builder builder = new SourceStampVerifier.Builder(
                DataSources.asDataSource(ByteBuffer.wrap(apkBytes)));
        if (minSdkVersionOverride != null) {
            builder.setMinCheckedPlatformVersion(minSdkVersionOverride);
        }
        if (maxSdkVersionOverride != null) {
            builder.setMaxCheckedPlatformVersion(maxSdkVersionOverride);
        }
        return builder.build().verifySourceStamp(expectedCertDigest);
    }

    private void assertVerified(SourceStampVerifier.Result result) {
        if (result.isVerified()) {
            return;
        }
        StringBuilder msg = new StringBuilder();
        for (ApkVerificationIssue error : result.getAllErrors()) {
            if (msg.length() > 0) {
                msg.append('\n');
            }
            msg.append(error.toString());
        }
        fail("APK failed source stamp verification: " + msg.toString());
    }

    private static void assertSourceStampVerificationFailure(SourceStampVerifier.Result result,
            int expectedIssueId) {
        if (result.isVerified()) {
            fail(
                    "APK source stamp verification succeeded instead of failing with "
                            + expectedIssueId);
            return;
        }

        StringBuilder msg = new StringBuilder();
        for (ApkVerificationIssue issue : result.getAllErrors()) {
            if (issue.getIssueId() == expectedIssueId) {
                return;
            }
            if (msg.length() > 0) {
                msg.append('\n');
            }
            msg.append(issue.toString());
        }

        fail(
                "APK source stamp failed verification for the wrong reason"
                        + ". Expected error ID: "
                        + expectedIssueId
                        + ", actual: "
                        + msg);
    }
}