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

package com.android.apksigner;

import com.android.apksig.ApkVerifier;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.List;

/**
 * Command-line tool for signing APKs and for checking whether an APK's signature are expected to
 * verify on Android devices.
 */
public class ApkSignerTool {

    private static final String VERSION = "0.0.0";
    private static final String HELP_PAGE_GENERAL = "help.txt";
    private static final String HELP_PAGE_VERIFY = "help_verify.txt";

    public static void main(String[] params) throws Exception {
        if ((params.length == 0) || ("--help".equals(params[0])) || ("-h".equals(params[0]))) {
            printUsage(HELP_PAGE_GENERAL);
            return;
        } else if ("--version".equals(params[0])) {
            System.out.println(VERSION);
            return;
        }

        String cmd = params[0];
        try {
            if ("sign".equals(cmd)) {
                sign(Arrays.copyOfRange(params, 1, params.length));
                return;
            } else if ("verify".equals(cmd)) {
                verify(Arrays.copyOfRange(params, 1, params.length));
                return;
            } else if ("help".equals(cmd)) {
                printUsage(HELP_PAGE_GENERAL);
                return;
            } else if ("version".equals(cmd)) {
                System.out.println(VERSION);
                return;
            } else {
                throw new ParameterException(
                        "Unsupported command: " + cmd + ". See --help for supported commands");
            }
        } catch (ParameterException | OptionsParser.OptionsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return;
        }
    }

    private static void sign(String[] params) throws Exception {
        throw new ParameterException("sign command not yet implemented");
    }

    private static void verify(String[] params) throws Exception {
        if (params.length == 0) {
            printUsage(HELP_PAGE_VERIFY);
            return;
        }

        int minSdkVersion = 1;
        int maxSdkVersion = Integer.MAX_VALUE;
        boolean printCerts = false;
        boolean verbose = false;
        boolean warningsTreatedAsErrors = false;
        OptionsParser optionsParser = new OptionsParser(params);
        String optionName;
        while ((optionName = optionsParser.nextOption()) != null) {
            String optionOriginalForm = optionsParser.getOptionOriginalForm();
            if ("min-sdk-version".equals(optionName)) {
                minSdkVersion = optionsParser.getRequiredIntValue("Mininimum API Level");
            } else if ("max-sdk-version".equals(optionName)) {
                minSdkVersion = optionsParser.getRequiredIntValue("Maximum API Level");
            } else if ("print-certs".equals(optionName)) {
                printCerts = optionsParser.getOptionalBooleanValue(true);
            } else if (("v".equals(optionName)) || ("verbose".equals(optionName))) {
                verbose = optionsParser.getOptionalBooleanValue(true);
            } else if ("Werr".equals(optionName)) {
                warningsTreatedAsErrors = optionsParser.getOptionalBooleanValue(true);
            } else if (("help".equals(optionName)) || ("h".equals(optionName))) {
                printUsage(HELP_PAGE_VERIFY);
                return;
            } else {
                throw new ParameterException(
                        "Unsupported option: " + optionOriginalForm + ". See --help for supported"
                                + " options.");
            }
        }
        if (minSdkVersion > maxSdkVersion) {
            throw new ParameterException(
                    "Min API Level (" + minSdkVersion + ") > max API Level (" + maxSdkVersion
                            + ")");
        }
        params = optionsParser.getRemainingParams();

        if (params.length < 1) {
            throw new ParameterException("Missing APK");
        } else if (params.length > 1) {
            throw new ParameterException("Unexpected parameter(s) after APK (" + params[0] + ")");
        }
        File inputApk = new File(params[0]);

        ApkVerifier.Result result =
                new ApkVerifier.Builder(inputApk)
                .setCheckedPlatformVersions(minSdkVersion, maxSdkVersion)
                .build()
                .verify();
        boolean verified = result.isVerified();

        boolean warningsEncountered = false;
        if (verified) {
            List<X509Certificate> signerCerts = result.getSignerCertificates();
            if (verbose) {
                System.out.println("Verifies");
                System.out.println(
                        "Verified using v1 scheme (JAR signing): "
                                + result.isVerifiedUsingV1Scheme());
                System.out.println(
                        "Verified using v2 scheme (APK Signature Scheme v2): "
                                + result.isVerifiedUsingV2Scheme());
                System.out.println("Number of signers: " + signerCerts.size());
            }
            if (printCerts) {
                int signerNumber = 0;
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
                for (X509Certificate signerCert : signerCerts) {
                    signerNumber++;
                    System.out.println(
                            "Signer #" + signerNumber + " certificate DN"
                                    + ": " + signerCert.getSubjectDN());
                    byte[] encodedCert = signerCert.getEncoded();
                    System.out.println(
                            "Signer #" + signerNumber + " certificate SHA-256 digest: "
                                    + HexEncoding.encode(sha256.digest(encodedCert)));
                    System.out.println(
                            "Signer #" + signerNumber + " certificate SHA-1 digest: "
                                    + HexEncoding.encode(sha1.digest(encodedCert)));
                    if (verbose) {
                        PublicKey publicKey = signerCert.getPublicKey();
                        System.out.println(
                                "Signer #" + signerNumber + " key algorithm: "
                                        + publicKey.getAlgorithm());
                        int keySize = -1;
                        if (publicKey instanceof RSAKey) {
                            keySize = ((RSAKey) publicKey).getModulus().bitLength();
                        } else if (publicKey instanceof ECKey) {
                            keySize = ((ECKey) publicKey).getParams()
                                    .getOrder().bitLength();
                        } else if (publicKey instanceof DSAKey) {
                            // DSA parameters may be inherited from the certificate. We
                            // don't handle this case at the moment.
                            DSAParams dsaParams = ((DSAKey) publicKey).getParams();
                            if (dsaParams != null) {
                                keySize = dsaParams.getP().bitLength();
                            }
                        }
                        System.out.println(
                                "Signer #" + signerNumber + " key size (bits): "
                                        + ((keySize != -1)
                                                ? String.valueOf(keySize) : "n/a"));
                        byte[] encodedKey = publicKey.getEncoded();
                        System.out.println(
                                "Signer #" + signerNumber + " public key SHA-256 digest: "
                                        + HexEncoding.encode(sha256.digest(encodedKey)));
                        System.out.println(
                                "Signer #" + signerNumber + " public key SHA-1 digest: "
                                        + HexEncoding.encode(sha1.digest(encodedKey)));
                    }
                }
            }
        } else {
            System.err.println("DOES NOT VERIFY");
        }

        for (ApkVerifier.IssueWithParams error : result.getErrors()) {
            System.err.println("ERROR: " + error);
        }

        @SuppressWarnings("resource") // false positive -- this resource is not opened here
        PrintStream warningsOut = (warningsTreatedAsErrors) ? System.err : System.out;
        for (ApkVerifier.IssueWithParams warning : result.getWarnings()) {
            warningsEncountered = true;
            warningsOut.println("WARNING: " + warning);
        }
        for (ApkVerifier.Result.V1SchemeSignerInfo signer : result.getV1SchemeSigners()) {
            String signerName = signer.getName();
            for (ApkVerifier.IssueWithParams error : signer.getErrors()) {
                System.err.println("ERROR: JAR signer " + signerName + ": " + error);
            }
            for (ApkVerifier.IssueWithParams warning : signer.getWarnings()) {
                warningsEncountered = true;
                warningsOut.println("WARNING: JAR signer " + signerName + ": " + warning);
            }
        }
        for (ApkVerifier.Result.V2SchemeSignerInfo signer : result.getV2SchemeSigners()) {
            String signerName = "signer #" + (signer.getIndex() + 1);
            for (ApkVerifier.IssueWithParams error : signer.getErrors()) {
                System.err.println(
                        "ERROR: APK Signature Scheme v2 " + signerName + ": " + error);
            }
            for (ApkVerifier.IssueWithParams warning : signer.getWarnings()) {
                warningsEncountered = true;
                warningsOut.println(
                        "WARNING: APK Signature Scheme v2 " + signerName + ": " + warning);
            }
        }

        if (!verified) {
            System.exit(1);
            return;
        }
        if ((warningsTreatedAsErrors) && (warningsEncountered)) {
            System.exit(1);
            return;
        }
    }

    private static void printUsage(String page) {
        try (BufferedReader in =
                new BufferedReader(
                        new InputStreamReader(
                                ApkSignerTool.class.getResourceAsStream(page),
                                StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read " + page + " resource");
        }
    }

    /**
     * Indicates that there is an issue with command-line parameters provided to this tool.
     */
    private static class ParameterException extends Exception {
        private static final long serialVersionUID = 1L;

        ParameterException(String message) {
            super(message);
        }
    }
}
