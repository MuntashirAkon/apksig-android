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

package com.android.apksig.internal.apk.v4;

import static com.android.apksig.internal.apk.ApkSigningBlockUtils.toHex;
import static com.android.apksig.internal.apk.SignatureAlgorithm.VERITY_DSA_WITH_SHA256;
import static com.android.apksig.internal.apk.SignatureAlgorithm.VERITY_ECDSA_WITH_SHA256;
import static com.android.apksig.internal.apk.SignatureAlgorithm.VERITY_RSA_PKCS1_V1_5_WITH_SHA256;
import static com.android.apksig.internal.pkcs7.AlgorithmIdentifier.getJcaSignatureAlgorithm;
import static com.android.apksig.internal.x509.Certificate.findCertificate;
import static com.android.apksig.internal.x509.Certificate.parseCertificates;

import com.android.apksig.ApkVerifier;
import com.android.apksig.ApkVerifier.Issue;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.asn1.Asn1BerParser;
import com.android.apksig.internal.asn1.Asn1DecodingException;
import com.android.apksig.internal.pkcs7.ContentInfo;
import com.android.apksig.internal.pkcs7.Pkcs7Constants;
import com.android.apksig.internal.pkcs7.SignedData;
import com.android.apksig.internal.pkcs7.SignerInfo;
import com.android.apksig.internal.util.ByteBufferUtils;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.proto.V4.V4Signature;
import com.android.apksig.util.DataSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * APK Signature Scheme V4 verifier.
 *
 * Verifies the serialized V4Signature protobuf against an APK.
 */
public abstract class V4SchemeVerifier {
    /** Hidden constructor to prevent instantiation. */
    private V4SchemeVerifier() {
    }

    /**
     * <p>
     * The main goals of the verifier are:
     * 1) parse V4Signature protobuf fields
     * 2) verifies the PKCS7 signature block against the raw root hash bytes in the proto field
     * 3) verifies that the raw root hash matches with the actual hash tree root of the give APK
     * 4) if the protobuf contains a verity tree, verifies that it matches with the actual verity
     * tree computed from the given APK.
     * </p>
     */
    public static ApkSigningBlockUtils.Result verify(DataSource apk, File v4SignatureFile)
            throws IOException, NoSuchAlgorithmException {
        final FileInputStream fileInput = new FileInputStream(v4SignatureFile);
        final V4Signature proto = V4Signature.parseFrom(fileInput);
        final ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(
                ApkSigningBlockUtils.VERSION_APK_SIGNATURE_SCHEME_V4);

        final byte[] pkcs7Signature = proto.getPkcs7SignatureBlock().toByteArray();
        final ByteBuffer pkcs7SignatureBlock =
                ByteBuffer.wrap(pkcs7Signature).order(ByteOrder.LITTLE_ENDIAN);

        final ByteBuffer verityRootHash = ByteBuffer.wrap(proto.getVerityRootHash().toByteArray());

        result.signers.add(parseAndVerifySignatureBlock(pkcs7SignatureBlock, verityRootHash));
        if (result.containsErrors()) {
            return result;
        }

        verifyRootHashAndTree(apk, result, proto.getVerityRootHash().toByteArray(),
                proto.getVerityTree().toByteArray());
        if (!result.containsErrors()) {
            result.verified = true;
        }
        // Add v3Content digest from the protobuf to the result
        result.signers.get(0).contentDigests.add(
                new ApkSigningBlockUtils.Result.SignerInfo.ContentDigest(
                        0 /* signature algorithm id doesn't matter here */,
                        proto.getV3Digest().toByteArray()));
        return result;
    }

    /**
     * Parses the provided pkcs7 signature block and populates the {@code result}.
     *
     * This verifies {@pkcs7SignatureBlock} over {@code verityRootHash}, as well as
     * parsing the certificate contained in the signature block.
     * This method adds one or more errors to the {@code result}.
     */
    private static ApkSigningBlockUtils.Result.SignerInfo parseAndVerifySignatureBlock(
            ByteBuffer pkcs7SignatureBlock,
            ByteBuffer verityRootHash) {
        final ApkSigningBlockUtils.Result.SignerInfo result =
                new ApkSigningBlockUtils.Result.SignerInfo();
        SignedData signedData;
        try {
            final ContentInfo contentInfo =
                    Asn1BerParser.parse(pkcs7SignatureBlock, ContentInfo.class);
            if (!Pkcs7Constants.OID_SIGNED_DATA.equals(contentInfo.contentType)) {
                result.addError(Issue.V4_SIG_MALFORMED_PKCS7,
                        "Unsupported ContentInfo.contentType: "
                                + contentInfo.contentType);
            }
            signedData = Asn1BerParser.parse(contentInfo.content.getEncoded(), SignedData.class);
        } catch (Asn1DecodingException e) {
            e.printStackTrace();
            result.addError(Issue.V4_SIG_MALFORMED_PKCS7, e);
            return result;
        }

        if (signedData.signerInfos.isEmpty()) {
            result.addError(Issue.V4_SIG_NO_SIGNER);
            return result;
        }

        if (signedData.signerInfos.size() != 1) {
            result.addError(Issue.V4_SIG_MULTIPLE_SIGNERS);
            return result;
        }
        // Embedded root hash should be equal to the external one
        ByteBuffer embeddedRootHash = signedData.encapContentInfo.content;
        if (!embeddedRootHash.equals(verityRootHash)) {
            result.addError(Issue.V4_SIG_ROOT_HASH_MISMATCH_BETWEEN_ATTACHED_DATA_AND_PROTO);
            return result;
        }

        SignerInfo unverifiedSignerInfo = signedData.signerInfos.get(0);

        List<X509Certificate> signedDataCertificates;
        try {
            signedDataCertificates = parseCertificates(signedData.certificates);
        } catch (CertificateException e) {
            result.addError(Issue.V4_SIG_MALFORMED_CERTIFICATE, e);
            return result;
        }

        // Verify SignerInfo
        verifySignerInfo(signedDataCertificates, unverifiedSignerInfo, verityRootHash, result);
        return result;
    }

    private static void verifySignerInfo(
            List<X509Certificate> signedDataCertificates, SignerInfo signerInfo,
            ByteBuffer data, ApkSigningBlockUtils.Result.SignerInfo result) {
        final String digestAlgorithmOid = signerInfo.digestAlgorithm.algorithm;
        final String signatureAlgorithmOid = signerInfo.signatureAlgorithm.algorithm;
        final X509Certificate signingCertificate =
                findCertificate(signedDataCertificates, signerInfo.sid);
        result.certs.clear();
        result.certs.add(signingCertificate);
        if (signingCertificate == null) {
            result.addError(Issue.V4_SIG_NO_CERTIFICATE);
            return;
        }
        // Check whether the signing certificate is acceptable. Android performs these
        // checks explicitly, instead of delegating this to
        // Signature.initVerify(Certificate).
        if (signingCertificate.hasUnsupportedCriticalExtension()) {
            result.addError(Issue.V4_SIG_MALFORMED_CERTIFICATE,
                    "Signing certificate has unsupported critical extensions");
            return;
        }
        final boolean[] keyUsageExtension = signingCertificate.getKeyUsage();
        if (keyUsageExtension != null) {
            boolean digitalSignature =
                    (keyUsageExtension.length >= 1) && (keyUsageExtension[0]);
            boolean nonRepudiation =
                    (keyUsageExtension.length >= 2) && (keyUsageExtension[1]);
            if ((!digitalSignature) && (!nonRepudiation)) {
                result.addError(Issue.V4_SIG_MALFORMED_CERTIFICATE,
                        "Signing certificate not authorized for use in digital signatures"
                                + ": keyUsage extension missing digitalSignature and"
                                + " nonRepudiation");
                return;
            }
        }

        Signature s = null;
        try {
            final String jcaSignatureAlgorithm = getJcaSignatureAlgorithm(
                    digestAlgorithmOid, signatureAlgorithmOid);
            s = Signature.getInstance(jcaSignatureAlgorithm);
        } catch (SignatureException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (s == null) {
            result.addError(Issue.V4_SIG_UNKNOWN_SIG_ALGORITHM);
            return;
        }
        if (signerInfo.signedAttrs != null) {
            result.addError(Issue.V4_SIG_MALFORMED_SIGNERS, "Should not contain signed attributes");
        }
        try {
            s.initVerify(signingCertificate.getPublicKey());
            s.update(data);
            final byte[] sigBytes = ByteBufferUtils.toByteArray(signerInfo.signature.slice());
            if (!s.verify(sigBytes)) {
                result.addError(Issue.V4_SIG_DID_NOT_VERIFY);
            }
        } catch (InvalidKeyException | SignatureException e) {
            result.addError(Issue.V4_SIG_VERIFY_EXCEPTION);
        }
    }

    private static void verifyRootHashAndTree(DataSource apkContent,
            ApkSigningBlockUtils.Result result, byte[] rootHashInResult, byte[] treeInResult)
            throws IOException, NoSuchAlgorithmException {
        final Map<ContentDigestAlgorithm, Pair<byte[], byte[]>> actualContentDigests =
                new HashMap<>();
        ApkSigningBlockUtils.computeChunkVerityTreeAndDigest(apkContent, actualContentDigests);
        if (result.signers.size() != 1) {
            throw new RuntimeException("There should only be one signer for V4");
        }
        final ApkSigningBlockUtils.Result.SignerInfo signerInfo = result.signers.get(0);
        for (ApkSigningBlockUtils.Result.SignerInfo.ContentDigest expected
                : signerInfo.contentDigests) {
            final SignatureAlgorithm signatureAlgorithm =
                    SignatureAlgorithm.findById(expected.getSignatureAlgorithmId());
            if (signatureAlgorithm == null) {
                continue;
            }
            final ContentDigestAlgorithm contentDigestAlgorithm =
                    signatureAlgorithm.getContentDigestAlgorithm();
            // should not happen
            if (contentDigestAlgorithm != ContentDigestAlgorithm.VERITY_CHUNKED_SHA256) {
                continue;
            }
            final byte[] expectedDigest = expected.getValue();
            final byte[] actualDigest =
                    actualContentDigests.get(contentDigestAlgorithm).getSecond();
            final byte[] actualTree =
                    actualContentDigests.get(contentDigestAlgorithm).getFirst();
            if (!Arrays.equals(expectedDigest, actualDigest)
                    || !Arrays.equals(expectedDigest, rootHashInResult)) {
                signerInfo.addError(
                        ApkVerifier.Issue.V4_SIG_APK_ROOT_DID_NOT_VERIFY,
                        contentDigestAlgorithm,
                        toHex(expectedDigest),
                        toHex(actualDigest));
                continue;
            }
            // Only check verity tree if it is not empty
            if (treeInResult != null && !Arrays.equals(treeInResult, actualTree)) {
                signerInfo.addError(
                        ApkVerifier.Issue.V4_SIG_APK_TREE_DID_NOT_VERIFY,
                        contentDigestAlgorithm,
                        toHex(expectedDigest),
                        toHex(actualDigest));
                continue;
            }
            signerInfo.verifiedContentDigests.put(contentDigestAlgorithm, actualDigest);
        }
    }
}
