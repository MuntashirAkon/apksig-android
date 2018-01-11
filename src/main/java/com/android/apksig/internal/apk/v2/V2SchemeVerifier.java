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

package com.android.apksig.internal.apk.v2;

import com.android.apksig.ApkVerifier.Issue;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.apk.SignatureInfo;
import com.android.apksig.internal.util.ByteBufferUtils;
import com.android.apksig.internal.util.GuaranteedEncodedFormX509Certificate;
import com.android.apksig.util.DataSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * APK Signature Scheme v2 verifier.
 *
 * <p>APK Signature Scheme v2 is a whole-file signature scheme which aims to protect every single
 * bit of the APK, as opposed to the JAR Signature Scheme which protects only the names and
 * uncompressed contents of ZIP entries.
 *
 * @see <a href="https://source.android.com/security/apksigning/v2.html">APK Signature Scheme v2</a>
 */
public abstract class V2SchemeVerifier {

    private static final int APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a;

    /** Hidden constructor to prevent instantiation. */
    private V2SchemeVerifier() {}

    /**
     * Verifies the provided APK's APK Signature Scheme v2 signatures and returns the result of
     * verification. The APK must be considered verified only if
     * {@link ApkSigningBlockUtils.Result#verified} is
     * {@code true}. If verification fails, the result will contain errors -- see
     * {@link ApkSigningBlockUtils.Result#getErrors()}.
     *
     * <p>Verification succeeds iff the APK's APK Signature Scheme v2 signatures are expected to
     * verify on all Android platform versions in the {@code [minSdkVersion, maxSdkVersion]} range.
     * If the APK's signature is expected to not verify on any of the specified platform versions,
     * this method returns a result with one or more errors and whose
     * {@code Result.verified == false}, or this method throws an exception.
     *
     * @throws ApkFormatException if the APK is malformed
     * @throws NoSuchAlgorithmException if the APK's signatures cannot be verified because a
     *         required cryptographic algorithm implementation is missing
     * @throws ApkSigningBlockUtils.SignatureNotFoundException if no APK Signature Scheme v2
     * signatures are found
     * @throws IOException if an I/O error occurs when reading the APK
     */
    public static ApkSigningBlockUtils.Result verify(
            DataSource apk,
            ApkUtils.ZipSections zipSections,
            int minSdkVersion,
            int maxSdkVersion)
            throws IOException, ApkFormatException, NoSuchAlgorithmException,
            ApkSigningBlockUtils.SignatureNotFoundException {
        ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result();
        SignatureInfo signatureInfo =
                ApkSigningBlockUtils.findSignature(apk, zipSections,
                        APK_SIGNATURE_SCHEME_V2_BLOCK_ID , result);

        DataSource beforeApkSigningBlock = apk.slice(0, signatureInfo.apkSigningBlockOffset);
        DataSource centralDir =
                apk.slice(
                        signatureInfo.centralDirOffset,
                        signatureInfo.eocdOffset - signatureInfo.centralDirOffset);
        ByteBuffer eocd = signatureInfo.eocd;

        verify(beforeApkSigningBlock,
                signatureInfo.signatureBlock,
                centralDir,
                eocd,
                minSdkVersion,
                maxSdkVersion,
                result);
        return result;
    }

    /**
     * Verifies the provided APK's v2 signatures and outputs the results into the provided
     * {@code result}. APK is considered verified only if there are no errors reported in the
     * {@code result}. See {@link #verify(DataSource, ApkUtils.ZipSections, int, int)} for more
     * information about the contract of this method.
     *
     * @param result result populated by this method with interesting information about the APK,
     *        such as information about signers, and verification errors and warnings.
     */
    private static void verify(
            DataSource beforeApkSigningBlock,
            ByteBuffer apkSignatureSchemeV2Block,
            DataSource centralDir,
            ByteBuffer eocd,
            int minSdkVersion,
            int maxSdkVersion,
            ApkSigningBlockUtils.Result result)
            throws IOException, NoSuchAlgorithmException {
        Set<ContentDigestAlgorithm> contentDigestsToVerify = new HashSet<>(1);
        parseSigners(apkSignatureSchemeV2Block, contentDigestsToVerify, minSdkVersion,
                maxSdkVersion, result);
        if (result.containsErrors()) {
            return;
        }
        ApkSigningBlockUtils.verifyIntegrity(
                beforeApkSigningBlock, centralDir, eocd, contentDigestsToVerify, result);
        if (!result.containsErrors()) {
            result.verified = true;
        }
    }

    /**
     * Parses each signer in the provided APK Signature Scheme v2 block and populates corresponding
     * {@code signerInfos} of the provided {@code result}.
     *
     * <p>This verifies signatures over {@code signed-data} block contained in each signer block.
     * However, this does not verify the integrity of the rest of the APK but rather simply reports
     * the expected digests of the rest of the APK (see {@code contentDigestsToVerify}).
     *
     * <p>This method adds one or more errors to the {@code result} if a verification error is
     * expected to be encountered on an Android platform version in the
     * {@code [minSdkVersion, maxSdkVersion]} range.
     */
    private static void parseSigners(
            ByteBuffer apkSignatureSchemeV2Block,
            Set<ContentDigestAlgorithm> contentDigestsToVerify,
            int minSdkVersion,
            int maxSdkVersion,
            ApkSigningBlockUtils.Result result) throws NoSuchAlgorithmException {
        ByteBuffer signers;
        try {
            signers = ApkSigningBlockUtils.getLengthPrefixedSlice(apkSignatureSchemeV2Block);
        } catch (ApkFormatException e) {
            result.addError(Issue.V2_SIG_MALFORMED_SIGNERS);
            return;
        }
        if (!signers.hasRemaining()) {
            result.addError(Issue.V2_SIG_NO_SIGNERS);
            return;
        }

        CertificateFactory certFactory;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to obtain X.509 CertificateFactory", e);
        }
        int signerCount = 0;
        while (signers.hasRemaining()) {
            int signerIndex = signerCount;
            signerCount++;
            ApkSigningBlockUtils.Result.SignerInfo signerInfo =
                    new ApkSigningBlockUtils.Result.SignerInfo();
            signerInfo.index = signerIndex;
            result.signers.add(signerInfo);
            try {
                ByteBuffer signer = ApkSigningBlockUtils.getLengthPrefixedSlice(signers);
                parseSigner(signer, certFactory, signerInfo, contentDigestsToVerify, minSdkVersion,
                        maxSdkVersion);
            } catch (ApkFormatException | BufferUnderflowException e) {
                signerInfo.addError(Issue.V2_SIG_MALFORMED_SIGNER);
                return;
            }
        }
    }

    /**
     * Parses the provided signer block and populates the {@code result}.
     *
     * <p>This verifies signatures over {@code signed-data} contained in this block but does not
     * verify the integrity of the rest of the APK. To facilitate APK integrity verification, this
     * method adds the {@code contentDigestsToVerify}. These digests can then be used to verify the
     * integrity of the APK.
     *
     * <p>This method adds one or more errors to the {@code result} if a verification error is
     * expected to be encountered on an Android platform version in the
     * {@code [minSdkVersion, maxSdkVersion]} range.
     */
    private static void parseSigner(
            ByteBuffer signerBlock,
            CertificateFactory certFactory,
            ApkSigningBlockUtils.Result.SignerInfo result,
            Set<ContentDigestAlgorithm> contentDigestsToVerify,
            int minSdkVersion,
            int maxSdkVersion)
                    throws ApkFormatException, NoSuchAlgorithmException {
        ByteBuffer signedData = ApkSigningBlockUtils.getLengthPrefixedSlice(signerBlock);
        byte[] signedDataBytes = new byte[signedData.remaining()];
        signedData.get(signedDataBytes);
        signedData.flip();
        result.signedData = signedDataBytes;

        ByteBuffer signatures = ApkSigningBlockUtils.getLengthPrefixedSlice(signerBlock);
        byte[] publicKeyBytes = ApkSigningBlockUtils.readLengthPrefixedByteArray(signerBlock);

        // Parse the signatures block and identify supported signatures
        int signatureCount = 0;
        List<SupportedSignature> supportedSignatures = new ArrayList<>(1);
        while (signatures.hasRemaining()) {
            signatureCount++;
            try {
                ByteBuffer signature = ApkSigningBlockUtils.getLengthPrefixedSlice(signatures);
                int sigAlgorithmId = signature.getInt();
                byte[] sigBytes = ApkSigningBlockUtils.readLengthPrefixedByteArray(signature);
                result.signatures.add(
                        new ApkSigningBlockUtils.Result.SignerInfo.Signature(
                                sigAlgorithmId, sigBytes));
                SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(sigAlgorithmId);
                if (signatureAlgorithm == null) {
                    result.addWarning(Issue.V2_SIG_UNKNOWN_SIG_ALGORITHM, sigAlgorithmId);
                    continue;
                }
                supportedSignatures.add(new SupportedSignature(signatureAlgorithm, sigBytes));
            } catch (ApkFormatException | BufferUnderflowException e) {
                result.addError(Issue.V2_SIG_MALFORMED_SIGNATURE, signatureCount);
                return;
            }
        }
        if (result.signatures.isEmpty()) {
            result.addError(Issue.V2_SIG_NO_SIGNATURES);
            return;
        }

        // Verify signatures over signed-data block using the public key
        List<SupportedSignature> signaturesToVerify = null;
        try {
            signaturesToVerify = getSignaturesToVerify(supportedSignatures, minSdkVersion,
                    maxSdkVersion);
        } catch (ApkSigningBlockUtils.NoSupportedSignaturesException e) {
            result.addError(Issue.V2_SIG_NO_SUPPORTED_SIGNATURES);
            return;
        }
        for (SupportedSignature signature : signaturesToVerify) {
            SignatureAlgorithm signatureAlgorithm = signature.algorithm;
            String jcaSignatureAlgorithm =
                    signatureAlgorithm.getJcaSignatureAlgorithmAndParams().getFirst();
            AlgorithmParameterSpec jcaSignatureAlgorithmParams =
                    signatureAlgorithm.getJcaSignatureAlgorithmAndParams().getSecond();
            String keyAlgorithm = signatureAlgorithm.getJcaKeyAlgorithm();
            PublicKey publicKey;
            try {
                publicKey =
                        KeyFactory.getInstance(keyAlgorithm).generatePublic(
                                new X509EncodedKeySpec(publicKeyBytes));
            } catch (Exception e) {
                result.addError(Issue.V2_SIG_MALFORMED_PUBLIC_KEY, e);
                return;
            }
            try {
                Signature sig = Signature.getInstance(jcaSignatureAlgorithm);
                sig.initVerify(publicKey);
                if (jcaSignatureAlgorithmParams != null) {
                    sig.setParameter(jcaSignatureAlgorithmParams);
                }
                signedData.position(0);
                sig.update(signedData);
                byte[] sigBytes = signature.signature;
                if (!sig.verify(sigBytes)) {
                    result.addError(Issue.V2_SIG_DID_NOT_VERIFY, signatureAlgorithm);
                    return;
                }
                result.verifiedSignatures.put(signatureAlgorithm, sigBytes);
                contentDigestsToVerify.add(signatureAlgorithm.getContentDigestAlgorithm());
            } catch (InvalidKeyException | InvalidAlgorithmParameterException
                    | SignatureException e) {
                result.addError(Issue.V2_SIG_VERIFY_EXCEPTION, signatureAlgorithm, e);
                return;
            }
        }

        // At least one signature over signedData has verified. We can now parse signed-data.
        signedData.position(0);
        ByteBuffer digests = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
        ByteBuffer certificates = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
        ByteBuffer additionalAttributes = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);

        // Parse the certificates block
        int certificateIndex = -1;
        while (certificates.hasRemaining()) {
            certificateIndex++;
            byte[] encodedCert = ApkSigningBlockUtils.readLengthPrefixedByteArray(certificates);
            X509Certificate certificate;
            try {
                certificate =
                        (X509Certificate)
                                certFactory.generateCertificate(
                                        new ByteArrayInputStream(encodedCert));
            } catch (CertificateException e) {
                result.addError(
                        Issue.V2_SIG_MALFORMED_CERTIFICATE,
                        certificateIndex,
                        certificateIndex + 1,
                        e);
                return;
            }
            // Wrap the cert so that the result's getEncoded returns exactly the original encoded
            // form. Without this, getEncoded may return a different form from what was stored in
            // the signature. This is because some X509Certificate(Factory) implementations
            // re-encode certificates.
            certificate = new GuaranteedEncodedFormX509Certificate(certificate, encodedCert);
            result.certs.add(certificate);
        }

        if (result.certs.isEmpty()) {
            result.addError(Issue.V2_SIG_NO_CERTIFICATES);
            return;
        }
        X509Certificate mainCertificate = result.certs.get(0);
        byte[] certificatePublicKeyBytes = mainCertificate.getPublicKey().getEncoded();
        if (!Arrays.equals(publicKeyBytes, certificatePublicKeyBytes)) {
            result.addError(
                    Issue.V2_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD,
                    ApkSigningBlockUtils.toHex(certificatePublicKeyBytes),
                    ApkSigningBlockUtils.toHex(publicKeyBytes));
            return;
        }

        // Parse the digests block
        int digestCount = 0;
        while (digests.hasRemaining()) {
            digestCount++;
            try {
                ByteBuffer digest = ApkSigningBlockUtils.getLengthPrefixedSlice(digests);
                int sigAlgorithmId = digest.getInt();
                byte[] digestBytes = ApkSigningBlockUtils.readLengthPrefixedByteArray(digest);
                result.contentDigests.add(
                        new ApkSigningBlockUtils.Result.SignerInfo.ContentDigest(
                                sigAlgorithmId, digestBytes));
            } catch (ApkFormatException | BufferUnderflowException e) {
                result.addError(Issue.V2_SIG_MALFORMED_DIGEST, digestCount);
                return;
            }
        }

        List<Integer> sigAlgsFromSignaturesRecord = new ArrayList<>(result.signatures.size());
        for (ApkSigningBlockUtils.Result.SignerInfo.Signature signature : result.signatures) {
            sigAlgsFromSignaturesRecord.add(signature.getAlgorithmId());
        }
        List<Integer> sigAlgsFromDigestsRecord = new ArrayList<>(result.contentDigests.size());
        for (ApkSigningBlockUtils.Result.SignerInfo.ContentDigest digest : result.contentDigests) {
            sigAlgsFromDigestsRecord.add(digest.getSignatureAlgorithmId());
        }

        if (!sigAlgsFromSignaturesRecord.equals(sigAlgsFromDigestsRecord)) {
            result.addError(
                    Issue.V2_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS,
                    sigAlgsFromSignaturesRecord,
                    sigAlgsFromDigestsRecord);
            return;
        }

        // Parse the additional attributes block.
        int additionalAttributeCount = 0;
        while (additionalAttributes.hasRemaining()) {
            additionalAttributeCount++;
            try {
                ByteBuffer attribute =
                        ApkSigningBlockUtils.getLengthPrefixedSlice(additionalAttributes);
                int id = attribute.getInt();
                byte[] value = ByteBufferUtils.toByteArray(attribute);
                result.additionalAttributes.add(
                        new ApkSigningBlockUtils.Result.SignerInfo.AdditionalAttribute(id, value));
                result.addWarning(Issue.V2_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE, id);
            } catch (ApkFormatException | BufferUnderflowException e) {
                result.addError(
                        Issue.V2_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE, additionalAttributeCount);
                return;
            }
        }
    }

    /**
     * Returns the subset of signatures which are expected to be verified by at least one Android
     * platform version in the {@code [minSdkVersion, maxSdkVersion]} range. The returned result is
     * guaranteed to contain at least one signature.
     *
     * <p>Each Android platform version typically verifies exactly one signature from the provided
     * {@code signatures} set. This method returns the set of these signatures collected over all
     * requested platform versions. As a result, the result may contain more than one signature.
     *
     * @throws ApkSigningBlockUtils.NoSupportedSignaturesException if no supported signatures were
     *         found for an Android platform version in the range.
     */
    private static List<SupportedSignature> getSignaturesToVerify(
            List<SupportedSignature> signatures, int minSdkVersion, int maxSdkVersion)
            throws ApkSigningBlockUtils.NoSupportedSignaturesException {
        // Pick the signature with the strongest algorithm at all required SDK versions, to mimic
        // Android's behavior on those versions.
        //
        // Here we assume that, once introduced, a signature algorithm continues to be supported in
        // all future Android versions. We also assume that the better-than relationship between
        // algorithms is exactly the same on all Android platform versions (except that older
        // platforms might support fewer algorithms). If these assumption are no longer true, the
        // logic here will need to change accordingly.
        Map<Integer, SupportedSignature> bestSigAlgorithmOnSdkVersion = new HashMap<>();
        int minProvidedSignaturesVersion = Integer.MAX_VALUE;
        for (SupportedSignature sig : signatures) {
            SignatureAlgorithm sigAlgorithm = sig.algorithm;
            int sigMinSdkVersion = sigAlgorithm.getMinSdkVersion();
            if (sigMinSdkVersion > maxSdkVersion) {
                continue;
            }
            if (sigMinSdkVersion < minProvidedSignaturesVersion) {
                minProvidedSignaturesVersion = sigMinSdkVersion;
            }

            SupportedSignature candidate = bestSigAlgorithmOnSdkVersion.get(sigMinSdkVersion);
            if ((candidate == null)
                    || (ApkSigningBlockUtils.compareSignatureAlgorithm(
                            sigAlgorithm, candidate.algorithm) > 0)) {
                bestSigAlgorithmOnSdkVersion.put(sigMinSdkVersion, sig);
            }
        }

        // Must have some supported signature algorithms for minSdkVersion.
        if (minSdkVersion < minProvidedSignaturesVersion) {
            throw new ApkSigningBlockUtils.NoSupportedSignaturesException(
                    "Minimum provided signature version " + minProvidedSignaturesVersion +
                    " < minSdkVersion " + minSdkVersion);
        }
        if (bestSigAlgorithmOnSdkVersion.isEmpty()) {
            throw new ApkSigningBlockUtils.NoSupportedSignaturesException("No supported signature");
        }
        return bestSigAlgorithmOnSdkVersion.values().stream()
                .sorted((sig1, sig2) -> Integer.compare(
                        sig1.algorithm.getId(), sig2.algorithm.getId()))
                .collect(Collectors.toList());
    }

    private static class SupportedSignature {
        private final SignatureAlgorithm algorithm;
        private final byte[] signature;

        private SupportedSignature(SignatureAlgorithm algorithm, byte[] signature) {
            this.algorithm = algorithm;
            this.signature = signature;
        }
    }

}
