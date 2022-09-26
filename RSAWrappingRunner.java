/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.amazonaws.cloudhsm.examples;

import com.cavium.asn1.Encoder;
import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.Util;
import com.cavium.key.CaviumKey;
import com.cavium.key.CaviumRSAPrivateKey;
import com.cavium.key.parameter.CaviumAESKeyGenParameterSpec;
import com.cavium.key.parameter.CaviumKeyGenAlgorithmParameterSpec;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import com.lowagie.text.DocumentException;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.*;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.util.HashMap;

/**
 * This sample demonstrates how to use RSA to wrap and unwrap a key into and out of the HSM.
 */
public class RSAWrappingRunner {
    private static byte[] COMMON_NAME_OID = new byte[] { (byte) 0x55, (byte) 0x04, (byte) 0x03 };
    private static byte[] COUNTRY_NAME_OID = new byte[] { (byte) 0x55, (byte) 0x04, (byte) 0x06 };
    private static byte[] LOCALITY_NAME_OID = new byte[] { (byte) 0x55, (byte) 0x04, (byte) 0x07 };
    private static byte[] STATE_OR_PROVINCE_NAME_OID = new byte[] { (byte) 0x55, (byte) 0x04, (byte) 0x08 };
    private static byte[] ORGANIZATION_NAME_OID = new byte[] { (byte) 0x55, (byte) 0x04, (byte) 0x0A };
    private static byte[] ORGANIZATION_UNIT_OID = new byte[] { (byte) 0x55, (byte) 0x04, (byte) 0x0B };

    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // Wrapping keys must be persistent.
        KeyPair wrappingKeyPair = new AsymmetricKeys().generateRSAKeyPairWithParams(2048, "RSA Wrapping Test", true, true);

        // Extractable keys must be marked extractable.
        Key extractableKey = generateExtractableKey(256, "Extractable key to wrap", false);

        // Using the wrapping keypair, wrap and unwrap the extractable key with OAEP wrapping.
//            rsaOAEPWrap(wrappingKeyPair.getPublic(), wrappingKeyPair.getPrivate(), extractableKey);

        // Using the wrapping keypair, wrap and unwrap the extractable key with RSA AES wrapping.

        // GET KEYS
        rsaAesWrap(wrappingKeyPair.getPublic(), wrappingKeyPair.getPrivate(), extractableKey);
        Key k = wrappingKeyPair.getPrivate();
        CaviumKey ck = (CaviumKey)k;

        System.out.printf("Key handle %d with label %s\n", ck.getHandle(), ck.getLabel());


        //GET SELF-SIGNED CERTIFICATE
        Certificate self_signed_cert = generateCert(wrappingKeyPair);
        Certificate[] chain = new Certificate[1];
        chain[0] = self_signed_cert;

        System.out.println("Certificate" + chain.length);
        System.out.println("Certificate" + chain[0].getEncoded());


        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        sign("/home/ec2-user/sign/aws-cloudhsm-jce-examples/sample.pdf", chain, k);


        // Unwrap a key as non-extractable and persistent.
//            Key unwrappedPersistentKey = rsaUnwrapWithSpecification(wrappingKeyPair);
//
//            // Clean up the keys.
//            Util.deleteKey((CaviumKey) wrappingKeyPair.getPrivate());
//            Util.deleteKey((CaviumKey) extractableKey);
//            Util.deleteKey((CaviumKey) unwrappedPersistentKey);
    }

    /**
     * Using the wrapping keypair, wrap and unwrap the extractable key with RSAAESWrap.
     *
     * @param wrappingKey
     * @param extractableKey
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     */
    private static void rsaAesWrap(Key wrappingKey, Key unwrappingKey, Key extractableKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("RSAAESWrap", "Cavium");
        cipher.init(Cipher.WRAP_MODE, wrappingKey);

        // Wrap the extractable key using the wrappingKey.
        byte[] wrappedBytes = cipher.wrap(extractableKey);

        // Unwrap using the SunJCE.
        cipher.init(Cipher.UNWRAP_MODE, unwrappingKey);
        Key unwrappedExtractableKey = cipher.unwrap(wrappedBytes, "AES", Cipher.SECRET_KEY);


//        Key handle = importKey(unwrappedExtractableKey, "alias", true, true);

//        // Compare the two keys.
//        // Notice that extractable keys can be exported from the HSM using the .getEncoded() method.
//        assert (Arrays.equals(extractableKey.getEncoded(), unwrappedExtractableKey.getEncoded()));
        System.out.printf("\nVerified key when using RSAAES inside the HSM to wrap and unwrap: %s\n", Base64.getEncoder().encodeToString(unwrappedExtractableKey.getEncoded()));
    }

    private static Certificate generateCert(KeyPair kp) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();
        byte[] version = Encoder.encodeConstructed((byte) 0, Encoder.encodePositiveBigInteger(new BigInteger("2"))); // version 1
        byte[] serialNo = Encoder.encodePositiveBigInteger(new BigInteger(1, Util.computeKCV(publicKey.getEncoded())));

        // Use the SHA512 OID and algorithm.
        byte[] signatureOid = new byte[] {
                (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xF7, (byte) 0x0D, (byte) 0x01, (byte) 0x01, (byte) 0x0D };
        String sigAlgoName = "SHA512WithRSA";

        byte[] signatureId = Encoder.encodeSequence(
                Encoder.encodeOid(signatureOid),
                Encoder.encodeNull());

        byte[] issuer = Encoder.encodeSequence(
                encodeName(COUNTRY_NAME_OID, "IN"),
                encodeName(STATE_OR_PROVINCE_NAME_OID, "UP"),
                encodeName(LOCALITY_NAME_OID, "Noida"),
                encodeName(ORGANIZATION_NAME_OID, "Adobe"),
                encodeName(ORGANIZATION_UNIT_OID, "Document Cloud"),
                encodeName(COMMON_NAME_OID, "CSC-Hackweek-Alpine")
        );

        Calendar c = Calendar.getInstance();
        c.add(Calendar.DAY_OF_YEAR, -1);
        Date notBefore = c.getTime();
        c.add(Calendar.YEAR, 1);
        Date notAfter = c.getTime();
        byte[] validity = Encoder.encodeSequence(
                Encoder.encodeUTCTime(notBefore),
                Encoder.encodeUTCTime(notAfter)
        );
        byte[] key = publicKey.getEncoded();

        byte[] certificate = Encoder.encodeSequence(
                version,
                serialNo,
                signatureId,
                issuer,
                validity,
                issuer,
                key);
        Signature sig;
        byte[] signature = null;
        try {
            sig = Signature.getInstance(sigAlgoName, "Cavium");
            sig.initSign(privateKey);
            sig.update(certificate);
            signature = Encoder.encodeBitstring(sig.sign());

        } catch (Exception e) {
            System.err.println(e.getMessage());
            return null;
        }

        byte [] x509 = Encoder.encodeSequence(
                certificate,
                signatureId,
                signature
        );
        return cf.generateCertificate(new ByteArrayInputStream(x509));
    }

    private static byte[] encodeName(byte[] nameOid, String value) {
        byte[] name = null;
        name = Encoder.encodeSet(
                Encoder.encodeSequence(
                        Encoder.encodeOid(nameOid),
                        Encoder.encodePrintableString(value)
                )
        );
        return name;
    }

    public static void sign(String src, Certificate[] chain, Key k) throws IOException, DocumentException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, CertificateEncodingException {
        PdfReader pdfReader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream("/home/ec2-user/sign/aws-cloudhsm-jce-examples/sample-out.pdf");
        PdfStamper signer = PdfStamper.createSignature(pdfReader, os, '\0');

        Calendar signDate = Calendar.getInstance();

        int page = 1;

        PdfSignature pdfSignature = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
        pdfSignature.setReason("Reason to sign");
        pdfSignature.setLocation("Location of signature");
        pdfSignature.setContact("Person Name");
        pdfSignature.setDate(new PdfDate(signDate));
        pdfSignature.setCert(chain[0].getEncoded());

        PdfSignatureAppearance appearance = createAppearance(signer, page, pdfSignature, chain);
        //PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        PdfPKCS7 sgn = new PdfPKCS7(null, chain, null, "SHA-256", null, false);
        InputStream data = appearance.getRangeStream();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(IOUtils.toByteArray(data));
        byte[] appeareanceHash = digest.digest();

        byte[] unsignedHash = sgn.getAuthenticatedAttributeBytes(appeareanceHash, appearance.getSignDate(), null);

        System.out.println("Hash: " + unsignedHash.length);

        byte[] signedHash = addDigitalSignatureToHash(unsignedHash, (PrivateKey)k);

        System.out.println("Hash: " + signedHash.length);

        sgn.setExternalDigest(signedHash, null, "RSA");
        byte[] encodedPKCS7 = sgn.getEncodedPKCS7(appeareanceHash, appearance.getSignDate());

        byte[] paddedSig = new byte[8192];

        System.arraycopy(encodedPKCS7, 0, paddedSig, 0, encodedPKCS7.length);

        PdfDictionary dictionary = new PdfDictionary();
        dictionary.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
        appearance.close(dictionary);
    }

    private static PdfSignatureAppearance createAppearance(PdfStamper signer, int page, PdfSignature pdfSignature, Certificate[] chain) throws IOException, DocumentException {
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setRender(PdfSignatureAppearance.SignatureRenderDescription);
        appearance.setAcro6Layers(true);

        int lowerLeftX = 570;
        int lowerLeftY = 70;
        int width = 370;
        int height = 150;
        appearance.setVisibleSignature(new Rectangle(lowerLeftX, lowerLeftY, width, height), page, null);

        appearance.setCryptoDictionary(pdfSignature);
        appearance.setCrypto(null, chain, null, PdfName.FILTER);

        HashMap<Object, Object> exclusions = new HashMap<>();
        exclusions.put(PdfName.CONTENTS, 8192 * 2 + 2);
        appearance.preClose(exclusions);

        return appearance;
    }

    public static byte[] addDigitalSignatureToHash(byte[] hashToSign, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(hashToSign);

        return signature.sign();
    }

    /**
     * Using the wrapping keypair, wrap and unwrap the extractable key with OAEP.
     * Use both the Cavium provider and the SunJCE to demonstrate compatibility. Note this works because the
     * wrapping keypair is marked "extractable". This allows the SunJCE to extract the unwrapping key before
     * performing the operation.
     *
     * @param wrappingKey
     * @param extractableKey
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     */
    private static void rsaOAEPWrap(Key wrappingKey, Key unwrappingKey, Key extractableKey)
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException {

        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256ANDMGF1Padding", "Cavium");
        cipher.init(Cipher.WRAP_MODE, wrappingKey, spec);

        // Wrap the extractable key using the wrappingKey.
        byte[] wrappedBytes = cipher.wrap(extractableKey);

        // Unwrap using the SunJCE.
        Cipher sunCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256ANDMGF1Padding", "SunJCE");
        sunCipher.init(Cipher.UNWRAP_MODE, unwrappingKey, spec);
        Key unwrappedExtractableKey = sunCipher.unwrap(wrappedBytes, "AES", Cipher.SECRET_KEY);

        // Compare the two keys.
        // Notice that extractable keys can be exported from the HSM using the .getEncoded() method.
        assert (Arrays.equals(extractableKey.getEncoded(), unwrappedExtractableKey.getEncoded()));
        System.out.printf("\nVerified key when using OAEP in the HSM and SunJCE to wrap and unwrap: %s\n", Base64.getEncoder().encodeToString(unwrappedExtractableKey.getEncoded()));
    }

    /**
     * Demonstrate how to unwrap a key using a Specification.
     * This example shows how to unwrap a key with specific label,
     * persistence, and extractable settings.
     *
     * @param wrappingKeyPair
     * @return
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     */
    private static Key rsaUnwrapWithSpecification(KeyPair wrappingKeyPair)
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException {

        // Generate a temporary key that we can wrap in the SunJCE
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        // Wrap the key and delete it.
        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        Cipher wrapCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256ANDMGF1Padding", "SunJCE");
        wrapCipher.init(Cipher.WRAP_MODE, wrappingKeyPair.getPublic(), spec);
        byte[] wrappedKeyBytes = wrapCipher.wrap(aesKey);

        // Create a specification to unwrap this key as non-extractable and persistent.
        CaviumKeyGenAlgorithmParameterSpec unwrappingSpec = new
                CaviumKeyGenAlgorithmParameterSpec("Testkey1", false, true);

        // Create a Cavium provider to unwrap the key.
        Key unwrappedKey = null;

        try {
            // We provide a Utility method to unwrap keys with a custom specification.
            // This allows customers to configure the persistence, extractability, and
            // labels of the keys they unwrap.
            unwrappedKey = Util.rsaUnwrapKey(
                    (CaviumRSAPrivateKey) wrappingKeyPair.getPrivate(),
                    wrappedKeyBytes,
                    "AES",
                    Cipher.SECRET_KEY,
                    unwrappingSpec,
                    "OAEPWithSHA-256ANDMGF1Padding");
        } catch (CFM2Exception ex) {
            throw new RuntimeException(ex);
        }

        System.out.printf("\nVerified key when using specification to unwrap: \n");
        System.out.printf("Key handle:  %d\n", ((CaviumKey) unwrappedKey).getHandle());
        System.out.printf("Persistent:  %b\n", ((CaviumKey) unwrappedKey).isPersistent());
        System.out.printf("Extractable: %b\n", ((CaviumKey) unwrappedKey).isExtractable());

        return unwrappedKey;
    }

    /**
     * Generate an extractable key that can be toggled persistent.
     * AES wrapping keys are required to be persistent. The keys being wrapped can be persistent or session keys.
     *
     * @param keySizeInBits
     * @param keyLabel
     * @return CaviumKey that is extractable and persistent.
     */
    private static Key generateExtractableKey(int keySizeInBits, String keyLabel, boolean isPersistent) {
        boolean isExtractable = true;

        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "Cavium");

            CaviumAESKeyGenParameterSpec aesSpec = new CaviumAESKeyGenParameterSpec(keySizeInBits, keyLabel, isExtractable, isPersistent);
            keyGen.init(aesSpec);
            SecretKey aesKey = keyGen.generateKey();

            return aesKey;

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        } catch (Exception e) {
            if (CFM2Exception.isAuthenticationFailure(e)) {
                System.out.println("Detected invalid credentials");
            } else if (CFM2Exception.isClientDisconnectError(e)) {
                System.out.println("Detected daemon network failure");
            }

            e.printStackTrace();
        }

        return null;
    }
}

