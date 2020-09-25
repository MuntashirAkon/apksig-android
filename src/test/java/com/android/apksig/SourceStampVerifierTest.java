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

import static com.android.apksig.apk.ApkUtilsLite.computeSha256DigestBytes;
import static com.android.apksig.internal.apk.ApkSigningBlockUtilsLite.toHex;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.android.apksig.SourceStampVerifier.Result;
import com.android.apksig.SourceStampVerifier.Result.SignerInfo;
import com.android.apksig.internal.util.Resources;
import com.android.apksig.util.DataSources;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.List;

@RunWith(JUnit4.class)
public class SourceStampVerifierTest {
    private static final String RSA_2048_CERT_SHA256_DIGEST =
            "fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8";
    private static final String RSA_2048_2_CERT_SHA256_DIGEST =
            "681b0e56a796350c08647352a4db800cc44b2adc8f4c72fa350bd05d4d50264d";
    private static final String RSA_2048_3_CERT_SHA256_DIGEST =
            "bb77a72efc60e66501ab75953af735874f82cfe52a70d035186a01b3482180f3";
    private static final String EC_P256_CERT_SHA256_DIGEST =
            "6a8b96e278e58f62cfe3584022cec1d0527fcb85a9e5d2e1694eb0405be5b599";
    private static final String EC_P256_2_CERT_SHA256_DIGEST =
            "d78405f761ff6236cc9b570347a570aba0c62a129a3ac30c831c64d09ad95469";

    @Test
    public void verifySourceStamp_correctSignature() throws Exception {
        Result verificationResult = verifySourceStamp("valid-stamp.apk");
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
    public void verifySourceStamp_rotatedV3Key_signingCertDigestsMatch() throws Exception {
        // The SourceStampVerifier should return a result that includes all of the latest signing
        // certificates for each of the signature schemes that are applicable to the specified
        // min / max SDK versions.

        // Verify when platform versions that support the V1 - V3 signature schemes are specified
        // that an APK signed with all signature schemes has its expected signers returned in the
        // result.
        Result verificationResult = verifySourceStamp("v1v2v3-rotated-v3-key-valid-stamp.apk", 23,
                28);
        assertVerified(verificationResult);
        assertSigningCertificates(verificationResult, EC_P256_CERT_SHA256_DIGEST,
                EC_P256_CERT_SHA256_DIGEST, EC_P256_2_CERT_SHA256_DIGEST);

        // Verify when the specified platform versions only support a single signature scheme that
        // scheme's signer is the only one in the result.
        verificationResult = verifySourceStamp("v1v2v3-rotated-v3-key-valid-stamp.apk", 18, 18);
        assertVerified(verificationResult);
        assertSigningCertificates(verificationResult, EC_P256_CERT_SHA256_DIGEST, null, null);

        verificationResult = verifySourceStamp("v1v2v3-rotated-v3-key-valid-stamp.apk", 24, 24);
        assertVerified(verificationResult);
        assertSigningCertificates(verificationResult, null, EC_P256_CERT_SHA256_DIGEST, null);

        verificationResult = verifySourceStamp("v1v2v3-rotated-v3-key-valid-stamp.apk", 28, 28);
        assertVerified(verificationResult);
        assertSigningCertificates(verificationResult, null, null, EC_P256_2_CERT_SHA256_DIGEST);
    }

    @Test
    public void verifySourceStamp_signatureMissing() throws Exception {
        Result verificationResult = verifySourceStamp(
                "stamp-without-block.apk");
        assertSourceStampVerificationFailure(verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_SIG_MISSING);
    }

    @Test
    public void verifySourceStamp_certificateMismatch() throws Exception {
        Result verificationResult = verifySourceStamp(
                "stamp-certificate-mismatch.apk");
        assertSourceStampVerificationFailure(
                verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK);
    }

    @Test
    public void verifySourceStamp_v1OnlySignatureValidStamp() throws Exception {
        Result verificationResult = verifySourceStamp("v1-only-with-stamp.apk");
        assertVerified(verificationResult);
        assertSigningCertificates(verificationResult, EC_P256_CERT_SHA256_DIGEST, null, null);

        // Confirm that the source stamp verification succeeds when specifying platform versions
        // that supported later signature scheme versions.
        verificationResult = verifySourceStamp("v1-only-with-stamp.apk", 28, 28);
        assertVerified(verificationResult);
        assertSigningCertificates(verificationResult, EC_P256_CERT_SHA256_DIGEST, null, null);

        verificationResult = verifySourceStamp("v1-only-with-stamp.apk", 24, 24);
        assertVerified(verificationResult);
        assertSigningCertificates(verificationResult, EC_P256_CERT_SHA256_DIGEST, null, null);
    }

    @Test
    public void verifySourceStamp_v2OnlySignatureValidStamp() throws Exception {
        // The SourceStampVerifier will not query the APK's manifest for the minSdkVersion, so
        // set the min / max versions to prevent failure due to a missing V1 signature.
        Result verificationResult = verifySourceStamp("v2-only-with-stamp.apk",
                24, 24);
        assertVerified(verificationResult);
        assertSigningCertificates(verificationResult, null, EC_P256_CERT_SHA256_DIGEST, null);

        // Confirm that the source stamp verification succeeds when specifying a platform version
        // that supports a later signature scheme version.
        verificationResult = verifySourceStamp("v2-only-with-stamp.apk", 28, 28);
        assertVerified(verificationResult);
        assertSigningCertificates(verificationResult, null, EC_P256_CERT_SHA256_DIGEST, null);
    }

    @Test
    public void verifySourceStamp_v3OnlySignatureValidStamp() throws Exception {
        // The SourceStampVerifier will not query the APK's manifest for the minSdkVersion, so
        // set the min / max versions to prevent failure due to a missing V1 signature.
        Result verificationResult = verifySourceStamp("v3-only-with-stamp.apk",
                28, 28);
        assertVerified(verificationResult);
        assertSigningCertificates(verificationResult, null, null, EC_P256_CERT_SHA256_DIGEST);
    }

    @Test
    public void verifySourceStamp_apkHashMismatch_v1SignatureScheme() throws Exception {
        Result verificationResult = verifySourceStamp(
                "stamp-apk-hash-mismatch-v1.apk");
        assertSourceStampVerificationFailure(verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_DID_NOT_VERIFY);
    }

    @Test
    public void verifySourceStamp_apkHashMismatch_v2SignatureScheme() throws Exception {
        Result verificationResult = verifySourceStamp(
                "stamp-apk-hash-mismatch-v2.apk");
        assertSourceStampVerificationFailure(verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_DID_NOT_VERIFY);
    }

    @Test
    public void verifySourceStamp_apkHashMismatch_v3SignatureScheme() throws Exception {
        Result verificationResult = verifySourceStamp(
                "stamp-apk-hash-mismatch-v3.apk");
        assertSourceStampVerificationFailure(verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_DID_NOT_VERIFY);
    }

    @Test
    public void verifySourceStamp_malformedSignature() throws Exception {
        Result verificationResult = verifySourceStamp(
                "stamp-malformed-signature.apk");
        assertSourceStampVerificationFailure(
                verificationResult, ApkVerificationIssue.SOURCE_STAMP_MALFORMED_SIGNATURE);
    }

    @Test
    public void verifySourceStamp_expectedDigestMatchesActual() throws Exception {
        // The ApkVerifier provides an API to specify the expected certificate digest; this test
        // verifies that the test runs through to completion when the actual digest matches the
        // provided value.
        Result verificationResult = verifySourceStamp("v3-only-with-stamp.apk",
                RSA_2048_CERT_SHA256_DIGEST, 28, 28);
        assertVerified(verificationResult);
    }

    @Test
    public void verifySourceStamp_expectedDigestMismatch() throws Exception {
        // If the caller requests source stamp verification with an expected cert digest that does
        // not match the actual digest in the APK the verifier should report the mismatch.
        Result verificationResult = verifySourceStamp("v3-only-with-stamp.apk",
                EC_P256_CERT_SHA256_DIGEST);
        assertSourceStampVerificationFailure(verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH);
    }

    @Test
    public void verifySourceStamp_noStampCertDigestNorSignatureBlock() throws Exception {
        // The caller of this API expects that the provided APK should be signed with a source
        // stamp; if no artifacts of the stamp are present ensure that the API fails indicating the
        // missing stamp.
        Result verificationResult = verifySourceStamp("original.apk");
        assertSourceStampVerificationFailure(verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING);
    }

    @Test
    public void verifySourceStamp_validStampLineage() throws Exception {
        Result verificationResult = verifySourceStamp(
                "stamp-lineage-valid.apk");
        assertVerified(verificationResult);
        assertSigningCertificatesInLineage(verificationResult, RSA_2048_CERT_SHA256_DIGEST,
                RSA_2048_2_CERT_SHA256_DIGEST);
    }

    @Test
    public void verifySourceStamp_invalidStampLineage() throws Exception {
        Result verificationResult = verifySourceStamp(
                "stamp-lineage-invalid.apk");
        assertSourceStampVerificationFailure(verificationResult,
                ApkVerificationIssue.SOURCE_STAMP_POR_CERT_MISMATCH);
    }

    @Test
    public void verifySourceStamp_multipleSignersInLineage() throws Exception {
        Result verificationResult = verifySourceStamp("stamp-lineage-with-3-signers.apk", 18, 28);
        assertVerified(verificationResult);
        assertSigningCertificatesInLineage(verificationResult, RSA_2048_CERT_SHA256_DIGEST,
                RSA_2048_2_CERT_SHA256_DIGEST, RSA_2048_3_CERT_SHA256_DIGEST);
    }

    @Test
    public void verifySourceStamp_noSignersInLineage_returnsEmptyLineage() throws Exception {
        // If the source stamp's signer has not yet been rotated then an empty lineage should be
        // returned.
        Result verificationResult = verifySourceStamp("valid-stamp.apk");
        assertSigningCertificatesInLineage(verificationResult);
    }

    @Test
    public void verifySourceStamp_noApkSignature_succeeds()
            throws Exception {
        // The SourceStampVerifier is designed to verify an APK's source stamp with minimal
        // verification of the APK signature schemes. This test verifies if just the MANIFEST.MF
        // is present without any other APK signatures the stamp signature can still be successfully
        // verified.
        Result verificationResult = verifySourceStamp("stamp-without-apk-signature.apk", 18, 28);
        assertVerified(verificationResult);
        assertSigningCertificates(verificationResult, null, null, null);
        // While the source stamp verification should succeed a warning should still be logged to
        // notify the caller that there were no signers.
        assertSourceStampVerificationWarning(verificationResult,
                ApkVerificationIssue.JAR_SIG_NO_SIGNATURES);
    }

    private Result verifySourceStamp(String apkFilenameInResources)
            throws Exception {
        return verifySourceStamp(apkFilenameInResources, null, null, null);
    }

    private Result verifySourceStamp(String apkFilenameInResources,
            String expectedCertDigest) throws Exception {
        return verifySourceStamp(apkFilenameInResources, expectedCertDigest, null, null);
    }

    private Result verifySourceStamp(String apkFilenameInResources,
            Integer minSdkVersionOverride, Integer maxSdkVersionOverride) throws Exception {
        return verifySourceStamp(apkFilenameInResources, null, minSdkVersionOverride,
                maxSdkVersionOverride);
    }

    private Result verifySourceStamp(String apkFilenameInResources,
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

    private static void assertVerified(Result result) {
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

    private static void assertSourceStampVerificationFailure(Result result, int expectedIssueId) {
        if (result.isVerified()) {
            fail(
                    "APK source stamp verification succeeded instead of failing with "
                            + expectedIssueId);
            return;
        }
        assertSourceStampVerificationIssue(result.getAllErrors(), expectedIssueId);
    }

    private static void assertSourceStampVerificationWarning(Result result, int expectedIssueId) {
        assertSourceStampVerificationIssue(result.getAllWarnings(), expectedIssueId);
    }

    private static void assertSourceStampVerificationIssue(List<ApkVerificationIssue> issues,
            int expectedIssueId) {
        StringBuilder msg = new StringBuilder();
        for (ApkVerificationIssue issue : issues) {
            if (issue.getIssueId() == expectedIssueId) {
                return;
            }
            if (msg.length() > 0) {
                msg.append('\n');
            }
            msg.append(issue.toString());
        }

        fail(
                "APK source stamp verification did not report the expected issue. "
                        + "Expected error ID: "
                        + expectedIssueId
                        + ", actual: "
                        + (msg.length() > 0 ? msg.toString() : "No reported issues"));
    }

    /**
     * Asserts that the provided {@code expectedCertDigests} match their respective signing
     * certificate digest in the specified {@code result}.
     *
     * <p>{@code expectedCertDigests} should be provided in order of the signature schemes with V1
     * being the first element, V2 the second, etc. If a signer is not expected to be present for
     * a signature scheme version a {@code null} value should be provided; for instance if only a V3
     * signing certificate is expected the following should be provided: {@code null, null,
     * v3ExpectedCertDigest}.
     *
     * <p>Note, this method only supports a single signer per signature scheme; if an expected
     * certificate digest is provided for a signature scheme and multiple signers are found an
     * assertion exception will be thrown.
     */
    private static void assertSigningCertificates(Result result, String... expectedCertDigests)
            throws Exception {
        for (int i = 0; i < expectedCertDigests.length; i++) {
            List<SignerInfo> signers = null;
            switch (i) {
                case 0:
                    signers = result.getV1SchemeSigners();
                    break;
                case 1:
                    signers = result.getV2SchemeSigners();
                    break;
                case 2:
                    signers = result.getV3SchemeSigners();
                    break;
                default:
                    fail("This method only supports verification of the signing certificates up "
                            + "through the V3 Signature Scheme");
            }
            if (expectedCertDigests[i] == null) {
                assertEquals(
                        "Did not expect any V" + (i + 1) + " signers, found " + signers.size(), 0,
                        signers.size());
                continue;
            }
            if (signers.size() != 1) {
                fail("Expected one V" + (i + 1) + " signer with certificate digest "
                        + expectedCertDigests[i] + ", found " + signers.size() + " V" + (i + 1)
                        + " signers");
            }
            X509Certificate signingCertificate = signers.get(0).getSigningCertificate();
            assertNotNull(signingCertificate);
            assertEquals(expectedCertDigests[i],
                    toHex(computeSha256DigestBytes(signingCertificate.getEncoded())));
        }
    }

    /**
     * Asserts that the provided {@code expectedCertDigests} match their respective certificate in
     * the source stamp's lineage with the oldest signer at element 0.
     *
     * <p>If no values are provided for the expectedCertDigests, the source stamp's lineage will
     * be checked for an empty {@code List} indicating the source stamp has not been rotated.
     */
    private static void assertSigningCertificatesInLineage(Result result,
            String... expectedCertDigests) throws Exception {
        List<X509Certificate> lineageCertificates =
                result.getSourceStampInfo().getCertificatesInLineage();
        assertEquals("Unexpected number of lineage certificates", expectedCertDigests.length,
                lineageCertificates.size());
        for (int i = 0; i < expectedCertDigests.length; i++) {
            assertEquals("Stamp lineage mismatch at signer " + i, expectedCertDigests[i],
                    toHex(computeSha256DigestBytes(lineageCertificates.get(i).getEncoded())));
        }
    }
}
