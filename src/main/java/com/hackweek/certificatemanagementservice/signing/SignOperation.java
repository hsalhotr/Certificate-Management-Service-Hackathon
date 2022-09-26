package com.hackweek.certificatemanagementservice.signing;

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

public class SignOperation {
    private static byte[] COMMON_NAME_OID = new byte[] { (byte) 0x55, (byte) 0x04, (byte) 0x03 };
    private static byte[] COUNTRY_NAME_OID = new byte[] { (byte) 0x55, (byte) 0x04, (byte) 0x06 };
    private static byte[] LOCALITY_NAME_OID = new byte[] { (byte) 0x55, (byte) 0x04, (byte) 0x07 };
    private static byte[] STATE_OR_PROVINCE_NAME_OID = new byte[] { (byte) 0x55, (byte) 0x04, (byte) 0x08 };
    private static byte[] ORGANIZATION_NAME_OID = new byte[] { (byte) 0x55, (byte) 0x04, (byte) 0x0A };
    private static byte[] ORGANIZATION_UNIT_OID = new byte[] { (byte) 0x55, (byte) 0x04, (byte) 0x0B };

    public static void performSignOps() throws Exception {

        // Wrapping keys must be persistent.
        KeyPair wrappingKeyPair = new AsymmetricKeys().generateRSAKeyPairWithParams(2048, "RSA Wrapping Test", true, true);

        // Extractable keys must be marked extractable.
        Key extractableKey = generateExtractableKey(256, "Extractable key to wrap", false);

        // GET KEYS
        rsaAesWrap(wrappingKeyPair.getPublic(), wrappingKeyPair.getPrivate(), extractableKey);
        Key k = wrappingKeyPair.getPrivate();
        CaviumKey ck = (CaviumKey)k;

        System.out.printf("Private Key handle %d with label %s\n", ck.getHandle(), ck.getLabel());


        //GET SELF-SIGNED CERTIFICATE
        Certificate self_signed_cert = generateCert(wrappingKeyPair);
        Certificate[] chain = new Certificate[1];
        chain[0] = self_signed_cert;

        System.out.println("Certificate Length: " + chain.length);


        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        sign("/home/ec2-user/files/inputDocument.pdf", "/home/ec2-user/output/signedDocument.pdf", chain, k);

    }

    private static void rsaAesWrap(Key wrappingKey, Key unwrappingKey, Key extractableKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("RSAAESWrap", "Cavium");
        cipher.init(Cipher.WRAP_MODE, wrappingKey);

        // Wrap the extractable key using the wrappingKey.
        byte[] wrappedBytes = cipher.wrap(extractableKey);

        // Unwrap using the SunJCE.
        cipher.init(Cipher.UNWRAP_MODE, unwrappingKey);
        Key unwrappedExtractableKey = cipher.unwrap(wrappedBytes, "AES", Cipher.SECRET_KEY);
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

    public static void sign(String src, String dest, Certificate[] chain, Key k) throws IOException, DocumentException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, CertificateEncodingException {
        PdfReader pdfReader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
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
