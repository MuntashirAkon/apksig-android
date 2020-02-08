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

import static com.android.apksig.internal.apk.ApkSigningBlockUtils.encodeCertificates;
import static com.android.apksig.internal.asn1.Asn1DerEncoder.ASN1_DER_NULL;
import static com.android.apksig.internal.oid.OidConstants.OID_DIGEST_SHA256;
import static com.android.apksig.internal.oid.OidConstants.OID_SIG_EC_PUBLIC_KEY;
import static com.android.apksig.internal.oid.OidConstants.OID_SIG_RSA;
import static com.android.apksig.internal.oid.OidConstants.OID_SIG_SHA256_WITH_DSA;

import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ApkSigningBlockUtils.SignerConfig;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.asn1.Asn1EncodingException;
import com.android.apksig.internal.pkcs7.AlgorithmIdentifier;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.util.DataSource;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * APK Signature Scheme V4 signer.
 * V4 scheme file contains 3 mandatory fields - used during installation.
 * And optional verity tree - has to be present during session commit.
 *
 * The fields:
 * <p>
 * 1. verityRootHash: bytes of the hash tree root (digest of first 1-page of the tree),
 * 2. V3Digest: digest from v2/v3 signing schema,
 * 3. pkcs7SignatureBlock: bytes of the signature over encoded signed data, which includes 1 and 2,
 * </p>
 * (optional) verityTree: integer size prepended bytes of the verity hash tree.
 *
 * TODO(schfan): Pass v3 digest to v4 signature proto and add verification code
 * TODO(schfan): Add v4 unit tests
 */
public abstract class V4SchemeSigner {
    /** Hidden constructor to prevent instantiation. */
    private V4SchemeSigner() {
    }

    /**
     * Based on a public key, return a signing algorithm that supports verity.
     */
    public static SignatureAlgorithm getSuggestedSignatureAlgorithm(PublicKey signingKey)
            throws InvalidKeyException {
        final String keyAlgorithm = signingKey.getAlgorithm();
        if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
            final int modulusLengthBits = ((RSAKey) signingKey).getModulus().bitLength();
            if (modulusLengthBits <= 3072) {
                return SignatureAlgorithm.VERITY_RSA_PKCS1_V1_5_WITH_SHA256;
            } else {
                // Keys longer than 3072 bit need to be paired with a stronger digest to avoid the
                // digest being the weak link. SHA-512 is the next strongest supported digest.
                throw new InvalidKeyException(
                        "Key requires SHA-512 signature algorithm, not yet supported with verity");
            }
        } else if ("DSA".equalsIgnoreCase(keyAlgorithm)) {
            return SignatureAlgorithm.VERITY_DSA_WITH_SHA256;
        } else if ("EC".equalsIgnoreCase(keyAlgorithm)) {
            final int keySizeBits = ((ECKey) signingKey).getParams().getOrder().bitLength();
            if (keySizeBits <= 256) {
                return SignatureAlgorithm.VERITY_ECDSA_WITH_SHA256;
            } else {
                throw new InvalidKeyException(
                        "Key requires SHA-512 signature algorithm, not yet supported with verity");
            }
        } else {
            throw new InvalidKeyException("Unsupported key algorithm: " + keyAlgorithm);
        }
    }

    /**
     * Compute hash tree and root for a given APK. Write the serialized protobuf to output file.
     */
    public static void generateV4Signature(
            DataSource apkContent,
            SignerConfig signerConfig,
            File outputFile)
            throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        Map<ContentDigestAlgorithm, Pair<byte[], byte[]>> verityDigest = new HashMap<>();
        ApkSigningBlockUtils.computeChunkVerityTreeAndDigest(apkContent, verityDigest);

        final Pair<V4Signature, byte[]> signaturePair;
        try {
            signaturePair = generateSignatureProto(signerConfig, verityDigest);
        } catch (InvalidKeyException | SignatureException |
                CertificateEncodingException | Asn1EncodingException e) {
            throw new InvalidKeyException("Signer failed", e);
        }

        V4Signature signature = signaturePair.getFirst();
        byte[] tree = signaturePair.getSecond();

        try (final DataOutputStream output = new DataOutputStream(
                new FileOutputStream(outputFile))) {
            signature.writeTo(output);

            if (tree != null && tree.length != 0) {
                V4Signature.writeBytes(output, tree);
            }
        }
    }

    private static Pair<V4Signature, byte[]> generateSignatureProto(
            SignerConfig signerConfig,
            Map<ContentDigestAlgorithm, Pair<byte[], byte[]>> contentDigests)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            CertificateEncodingException, Asn1EncodingException {
        if (signerConfig.certificates.isEmpty()) {
            throw new SignatureException("No certificates configured for signer");
        }
        final PublicKey publicKey = signerConfig.certificates.get(0).getPublicKey();

        final List<byte[]> certificates = encodeCertificates(signerConfig.certificates);
        if (certificates.size() != 1) {
            throw new CertificateEncodingException("Should only have one certificate");
        }

        if (signerConfig.signatureAlgorithms.size() != 1) {
            throw new SignatureException("Should only be one signature algorithm");
        }

        final SignatureAlgorithm signatureAlgorithm = signerConfig.signatureAlgorithms.get(0);
        final ContentDigestAlgorithm contentDigestAlgorithm =
                signatureAlgorithm.getContentDigestAlgorithm();
        final Pair<byte[], byte[]> contentDigest = contentDigests.get(contentDigestAlgorithm);
        if (contentDigest == null) {
            throw new SignatureException("Cannot find computed digest");
        }
        byte[] tree = contentDigest.getFirst();
        byte[] rootHash = contentDigest.getSecond();

        final List<Pair<Integer, byte[]>> signatures =
                ApkSigningBlockUtils.generateSignaturesOverData(
                        signerConfig, rootHash /* signed data */);
        if (signatures.size() != 1) {
            throw new SignatureException("Should only be one signature generated");
        }

        byte[] pkcs7SignatureBlock = ApkSigningBlockUtils.generatePkcs7DerEncodedMessage(
                signatures.get(0).getSecond(), /* signature bytes */
                ByteBuffer.wrap(rootHash),
                signerConfig.certificates,
                new AlgorithmIdentifier(OID_DIGEST_SHA256, ASN1_DER_NULL), /* digest algo id */
                getSignatureAlgorithmIdentifier(publicKey));

        final V4Signature signature = new V4Signature(rootHash, new byte[0], pkcs7SignatureBlock);
        return Pair.of(signature, tree);
    }

    /**
     * Returns the JCA SHA256 {@code AlgorithmIdentifier} and PKCS #7 {@code SignatureAlgorithm} to
     * use when signing with the specified key.
     */
    private static AlgorithmIdentifier getSignatureAlgorithmIdentifier(
            PublicKey publicKey) throws InvalidKeyException {
        String keyAlgorithm = publicKey.getAlgorithm();
        if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
            return new AlgorithmIdentifier(OID_SIG_RSA, ASN1_DER_NULL);
        } else if ("DSA".equalsIgnoreCase(keyAlgorithm)) {
            return new AlgorithmIdentifier(OID_SIG_SHA256_WITH_DSA, ASN1_DER_NULL);
        } else if ("EC".equalsIgnoreCase(keyAlgorithm)) {
            return new AlgorithmIdentifier(OID_SIG_EC_PUBLIC_KEY, ASN1_DER_NULL);
        } else {
            throw new InvalidKeyException("Unsupported key algorithm: " + keyAlgorithm);
        }
    }
}
