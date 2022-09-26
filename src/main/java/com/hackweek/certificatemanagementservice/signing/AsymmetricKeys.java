package com.hackweek.certificatemanagementservice.signing;

import com.cavium.key.parameter.CaviumECGenParameterSpec;
import com.cavium.key.parameter.CaviumRSAKeyGenParameterSpec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Asymmetric key generation examples.
 */
public class AsymmetricKeys {
    public KeyPair generateECKeyPair(String curveName, String label)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        boolean isExtractable = false;
        boolean isPersistent = false;

        return generateECKeyPairWithParams(curveName, label, isExtractable, isPersistent);
    }

    public KeyPair generateECKeyPairWithParams(String curveName, String label, boolean isExtractable, boolean isPersistent)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", "Cavium");
        keyPairGen.initialize(
                new CaviumECGenParameterSpec(
                        curveName,
                        label + ":public",
                        label + ":private",
                        isExtractable,
                        isPersistent));

        return keyPairGen.generateKeyPair();
    }

    public KeyPair generateRSAKeyPair(int keySizeInBits, String label)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        boolean isExtractable = false;
        boolean isPersistent = false;

        return generateRSAKeyPairWithParams(keySizeInBits, label, isExtractable, isPersistent);
    }

    public KeyPair generateRSAKeyPairWithParams(int keySizeInBits, String label, boolean isExtractable, boolean isPersistent)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("rsa", "Cavium");;
        CaviumRSAKeyGenParameterSpec spec = new CaviumRSAKeyGenParameterSpec(keySizeInBits, new BigInteger("65537"), label + ":public", label + ":private", isExtractable, isPersistent);

        keyPairGen.initialize(spec);

        return keyPairGen.generateKeyPair();
    }
}
