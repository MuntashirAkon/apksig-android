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

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkSignerEngine;
import com.android.apksig.ApkVerifier;
import com.android.apksig.DefaultApkSignerEngine;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

/**
 * Command-line tool for signing APKs and for checking whether an APK's signature are expected to
 * verify on Android devices.
 */
public class ApkSignerTool {

    private static final String VERSION = "0.0.0";
    private static final String HELP_PAGE_GENERAL = "help.txt";
    private static final String HELP_PAGE_SIGN = "help_sign.txt";
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
        if (params.length == 0) {
            printUsage(HELP_PAGE_SIGN);
            return;
        }

        File outputApk = null;
        boolean verbose = false;
        boolean v1SigningEnabled = true;
        boolean v2SigningEnabled = true;
        int minSdkVersion = 1;
        int maxSdkVersion = Integer.MAX_VALUE;
        List<SignerParams> signers = new ArrayList<>(1);
        SignerParams signerParams = new SignerParams();
        OptionsParser optionsParser = new OptionsParser(params);
        String optionName;
        while ((optionName = optionsParser.nextOption()) != null) {
            String optionOriginalForm = optionsParser.getOptionOriginalForm();
            if (("help".equals(optionName)) || ("h".equals(optionName))) {
                printUsage(HELP_PAGE_SIGN);
                return;
            } else if ("out".equals(optionName)) {
                outputApk = new File(optionsParser.getRequiredValue("Output file name"));
            } else if ("min-sdk-version".equals(optionName)) {
                minSdkVersion = optionsParser.getRequiredIntValue("Mininimum API Level");
            } else if ("max-sdk-version".equals(optionName)) {
                minSdkVersion = optionsParser.getRequiredIntValue("Maximum API Level");
            } else if ("v1-signing-enabled".equals(optionName)) {
                v1SigningEnabled = optionsParser.getOptionalBooleanValue(true);
            } else if ("v2-signing-enabled".equals(optionName)) {
                v2SigningEnabled = optionsParser.getOptionalBooleanValue(true);
            } else if ("next-signer".equals(optionName)) {
                if (!signerParams.isEmpty()) {
                    signers.add(signerParams);
                    signerParams = new SignerParams();
                }
            } else if ("ks".equals(optionName)) {
                signerParams.keystoreFile = optionsParser.getRequiredValue("KeyStore file");
            } else if ("ks-key-alias".equals(optionName)) {
                signerParams.keystoreKeyAlias =
                        optionsParser.getRequiredValue("KeyStore key alias");
            } else if ("ks-pass".equals(optionName)) {
                signerParams.keystorePasswordSpec =
                        optionsParser.getRequiredValue("KeyStore password");
            } else if ("key-pass".equals(optionName)) {
                signerParams.keyPasswordSpec = optionsParser.getRequiredValue("Key password");
            } else if ("v1-signer-name".equals(optionName)) {
                signerParams.v1SigFileBasename =
                        optionsParser.getRequiredValue("JAR signature file basename");
            } else if (("v".equals(optionName)) || ("verbose".equals(optionName))) {
                verbose = optionsParser.getOptionalBooleanValue(true);
            } else {
                throw new ParameterException(
                        "Unsupported option: " + optionOriginalForm + ". See --help for supported"
                                + " options.");
            }
        }
        if (!signerParams.isEmpty()) {
            signers.add(signerParams);
        }
        signerParams = null;

        if (minSdkVersion > maxSdkVersion) {
            throw new ParameterException(
                    "Min API Level (" + minSdkVersion + ") > max API Level (" + maxSdkVersion
                            + ")");
        }

        if (signers.isEmpty()) {
            throw new ParameterException("At least one signer must be specified");
        }

        params = optionsParser.getRemainingParams();
        if (params.length < 1) {
            throw new ParameterException("Missing input APK");
        } else if (params.length > 1) {
            throw new ParameterException(
                    "Unexpected parameter(s) after input APK (" + params[0] + ")");
        }
        File inputApk = new File(params[0]);
        if (outputApk == null) {
            outputApk = inputApk;
        }

        List<DefaultApkSignerEngine.SignerConfig> signerConfigs =
                new ArrayList<>(signers.size());
        int signerNumber = 0;
        try (PasswordRetriever passwordRetriever = new PasswordRetriever()) {
            for (SignerParams signer : signers) {
                signerNumber++;
                signer.name = "signer #" + signerNumber;
                try {
                    signer.loadPrivateKeyAndCerts(passwordRetriever);
                } catch (ParameterException e) {
                    System.err.println(
                            "Failed to load signer \"" + signer.name + "\": "
                                    + e.getMessage());
                    System.exit(2);
                    return;
                } catch (Exception e) {
                    System.err.println("Failed to load signer \"" + signer.name + "\"");
                    e.printStackTrace();
                    System.exit(2);
                    return;
                }
                String v1SigBasename;
                if (signer.v1SigFileBasename != null) {
                    v1SigBasename = signer.v1SigFileBasename;
                } else if (signer.keystoreKeyAlias != null) {
                    v1SigBasename = signer.keystoreKeyAlias;
                } else {
                    throw new RuntimeException("KeyStore key alias not available");
                }
                DefaultApkSignerEngine.SignerConfig signerConfig =
                        new DefaultApkSignerEngine.SignerConfig.Builder(
                                v1SigBasename, signer.privateKey, signer.certs)
                        .build();
                signerConfigs.add(signerConfig);
            }
        }

        ApkSignerEngine signerEngine =
                new DefaultApkSignerEngine.Builder(signerConfigs, minSdkVersion)
                .setOtherSignersSignaturesPreserved(false)
                .setV1SigningEnabled(v1SigningEnabled)
                .setV2SigningEnabled(v2SigningEnabled)
                .build();

        File tmpOutputApk;
        if (inputApk.getCanonicalPath().equals(outputApk.getCanonicalPath())) {
            tmpOutputApk = File.createTempFile("apksigner", ".apk");
            tmpOutputApk.deleteOnExit();
        } else {
            tmpOutputApk = outputApk;
        }
        new ApkSigner.Builder(signerEngine)
                .setInputApk(inputApk)
                .setOutputApk(tmpOutputApk)
                .build()
                .sign();
        if (tmpOutputApk != outputApk) {
            FileSystem fs = FileSystems.getDefault();
            Files.move(
                    fs.getPath(tmpOutputApk.getPath()),
                    fs.getPath(outputApk.getPath()),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.COPY_ATTRIBUTES);
        }

        if (verbose) {
            System.out.println("Signed");
        }
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

    private static class SignerParams {
        String name;

        String keystoreKeyAlias;
        String keystoreFile;
        String keystorePasswordSpec;
        String keyPasswordSpec;

        String v1SigFileBasename;

        PrivateKey privateKey;
        List<X509Certificate> certs;

        private boolean isEmpty() {
            return (name == null)
                    && (keystoreKeyAlias == null)
                    && (keystoreFile == null)
                    && (keystorePasswordSpec == null)
                    && (keyPasswordSpec == null)
                    && (v1SigFileBasename == null)
                    && (privateKey == null)
                    && (certs == null);
        }

        private void loadPrivateKeyAndCerts(PasswordRetriever passwordRetriever) throws Exception {
            loadPrivateKeyAndCertsFromKeyStore(passwordRetriever);
        }

        private void loadPrivateKeyAndCertsFromKeyStore(PasswordRetriever passwordRetriever)
                throws Exception {
            if (keystoreFile == null) {
                throw new ParameterException("KeyStore file must be specified (see --ks)");
            }

            // 1. Obtain a KeyStore implementation
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

            // 2. Load the KeyStore
            char[] keystorePwd = null;
            if ("NONE".equals(keystoreFile)) {
                ks.load(null);
            } else {
                boolean loaded = false;
                if (keystorePasswordSpec == null) {
                    // No password specified. Check whether the KeyStore loads without a password.
                    try {
                        try (FileInputStream in = new FileInputStream(keystoreFile)) {
                            ks.load(in, null);
                            loaded = true;
                        }
                    } catch (IOException e) {
                        if (e.getCause() instanceof UnrecoverableKeyException) {
                            // Looks like the KeyStore is password-protected
                            loaded = false;
                        } else {
                            throw e;
                        }
                    }
                }
                if (!loaded) {
                    String keystorePasswordSpec =
                            (this.keystorePasswordSpec != null)
                                    ?  this.keystorePasswordSpec : PasswordRetriever.SPEC_STDIN;
                    String keystorePwdString =
                            passwordRetriever.getPassword(
                                    keystorePasswordSpec, "Keystore password for " + name);
                    keystorePwd = keystorePwdString.toCharArray();
                    try (FileInputStream in = new FileInputStream(keystoreFile)) {
                        ks.load(in, keystorePwd);
                    }
                }
            }

            // 3. Load the PrivateKey and cert chain from KeyStore
            char[] keyPwd;
            if (keyPasswordSpec == null) {
                keyPwd = keystorePwd;
            } else {
                keyPwd =
                        passwordRetriever.getPassword(keyPasswordSpec, "Key password for " + name)
                                .toCharArray();
            }
            String keyAlias = null;
            PrivateKey key = null;
            try {
                if (keystoreKeyAlias == null) {
                    // Private key entry alias not specified. Find the key entry contained in this
                    // KeyStore. If the KeyStore contains multiple key entries, return an error.
                    Enumeration<String> aliases = ks.aliases();
                    if (aliases != null) {
                        while (aliases.hasMoreElements()) {
                            String entryAlias = aliases.nextElement();
                            if (ks.isKeyEntry(entryAlias)) {
                                keyAlias = entryAlias;
                                if (keystoreKeyAlias != null) {
                                    throw new ParameterException(
                                            keystoreFile + " contains multiple key entries"
                                            + ". --ks-key-alias option must be used to specify"
                                            + " which entry to use.");
                                }
                                keystoreKeyAlias = keyAlias;
                            }
                        }
                    }
                    if (keystoreKeyAlias == null) {
                        throw new ParameterException(
                                keystoreFile + " does not contain key entries");
                    }
                }

                // Private key entry alias known. Load that entry's private key.
                keyAlias = keystoreKeyAlias;
                if (!ks.isKeyEntry(keyAlias)) {
                    throw new ParameterException(
                            keystoreFile + " entry \"" + keyAlias + "\" does not contain a key");
                }
                Key entryKey;
                if (keyPwd != null) {
                    // Key password specified -- load this key as a password-protected key
                    entryKey = ks.getKey(keyAlias, keyPwd);
                } else {
                    // Key password not specified -- try to load this key without using a password
                    try {
                        entryKey = ks.getKey(keyAlias, null);
                    } catch (UnrecoverableKeyException expected) {
                        // Looks like this might be a password-protected key. Prompt for password
                        // and try loading the key using the password.
                        keyPwd =
                                passwordRetriever.getPassword(
                                        PasswordRetriever.SPEC_STDIN,
                                        "Password for key with alias \"" + keyAlias + "\"")
                                                .toCharArray();
                        entryKey = ks.getKey(keyAlias, keyPwd);
                    }
                }
                if (entryKey == null) {
                    throw new ParameterException(
                            keystoreFile + " entry \"" + keyAlias + "\" does not contain a key");
                } else if (!(entryKey instanceof PrivateKey)) {
                    throw new ParameterException(
                            keystoreFile + " entry \"" + keyAlias + "\" does not contain a private"
                                    + " key. It contains a key of algorithm: "
                                    + entryKey.getAlgorithm());
                }
                key = (PrivateKey) entryKey;
            } catch (UnrecoverableKeyException e) {
                throw new IOException(
                        "Failed to obtain key with alias \"" + keyAlias + "\" from " + keystoreFile
                                + ". Wrong password?",
                        e);
            }
            this.privateKey = key;
            Certificate[] certChain = ks.getCertificateChain(keyAlias);
            if ((certChain == null) || (certChain.length == 0)) {
                throw new ParameterException(
                        keystoreFile + " entry \"" + keyAlias + "\" does not contain certificates");
            }
            this.certs = new ArrayList<>(certChain.length);
            for (Certificate cert : certChain) {
                this.certs.add((X509Certificate) cert);
            }
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
