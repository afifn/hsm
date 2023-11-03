package utils;

import data.model.KeyMechanism;
import data.model.KeyPair;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

import java.util.ArrayList;
import java.util.List;

public class KeyConstant {
    public static List<KeyPair> keyPairs() {
        List<KeyPair> keyPairList = new ArrayList<>();
        keyPairList.add(new KeyPair("AES KEY GEN", PKCS11Constants.CKM_AES_KEY_GEN));
        keyPairList.add(new KeyPair("DES KEY GEN", PKCS11Constants.CKM_DES_KEY_GEN));
        keyPairList.add(new KeyPair("DES2 KEY GEN", PKCS11Constants.CKM_DES2_KEY_GEN));
        keyPairList.add(new KeyPair("DES3 KEY GEN", PKCS11Constants.CKM_DES3_KEY_GEN));
        keyPairList.add(new KeyPair("RSA Key Pair", PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN));
        keyPairList.add(new KeyPair("EC Key Pair", PKCS11Constants.CKM_EC_KEY_PAIR_GEN));
        return keyPairList;
    }

    public static List<KeyPair> keyPairSymmetric() {
        List<KeyPair> keyPairList = new ArrayList<>();
        keyPairList.add(new KeyPair("AES KEY GEN", PKCS11Constants.CKM_AES_KEY_GEN));
        keyPairList.add(new KeyPair("DES KEY GEN", PKCS11Constants.CKM_DES_KEY_GEN));
        keyPairList.add(new KeyPair("DES2 KEY GEN", PKCS11Constants.CKM_DES2_KEY_GEN));
        keyPairList.add(new KeyPair("DES3 KEY GEN", PKCS11Constants.CKM_DES3_KEY_GEN));
        return keyPairList;
    }
    public static List<KeyPair> keyPairAsymmetric() {
        List<KeyPair> keyPairList = new ArrayList<>();
        keyPairList.add(new KeyPair("RSA Key Pair", PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN));
        keyPairList.add(new KeyPair("EC Key Pair", PKCS11Constants.CKM_EC_KEY_PAIR_GEN));
        return keyPairList;
    }

    // ini perbatasan antara key pair dan key mechanism

    public static List<KeyMechanism> keyMechanisms() {
        List<KeyMechanism> keyMechanisms = new ArrayList<>();
        keyMechanisms.add(new KeyMechanism("AES CBC", PKCS11Constants.CKM_AES_CBC));
        keyMechanisms.add(new KeyMechanism("AES CBC PADDING", PKCS11Constants.CKM_AES_CBC_PAD));
        keyMechanisms.add(new KeyMechanism("AES ECB", PKCS11Constants.CKM_AES_ECB));
        keyMechanisms.add(new KeyMechanism("DES CBC", PKCS11Constants.CKM_DES_CBC));
        keyMechanisms.add(new KeyMechanism("DES CBC PADDING", PKCS11Constants.CKM_DES_CBC_PAD));
        keyMechanisms.add(new KeyMechanism("DES ECB", PKCS11Constants.CKM_DES_ECB));
        keyMechanisms.add(new KeyMechanism("DES3 CBC", PKCS11Constants.CKM_DES3_CBC));
        keyMechanisms.add(new KeyMechanism("DES3 CBC PADDING", PKCS11Constants.CKM_DES3_CBC_PAD));
        keyMechanisms.add(new KeyMechanism("DES3 ECB", PKCS11Constants.CKM_DES_ECB));
        keyMechanisms.add(new KeyMechanism("RSA PKCS", PKCS11Constants.CKM_RSA_PKCS));
        return keyMechanisms;
    }

    public static List<KeyMechanism> keyMechanismsSymmetric() {
        List<KeyMechanism> keyMechanisms = new ArrayList<>();
        keyMechanisms.add(new KeyMechanism("AES CBC", PKCS11Constants.CKM_AES_CBC));
        keyMechanisms.add(new KeyMechanism("AES CBC PADDING", PKCS11Constants.CKM_AES_CBC_PAD));
        keyMechanisms.add(new KeyMechanism("AES ECB", PKCS11Constants.CKM_AES_ECB));
        keyMechanisms.add(new KeyMechanism("DES CBC", PKCS11Constants.CKM_DES_CBC));
        keyMechanisms.add(new KeyMechanism("DES CBC PADDING", PKCS11Constants.CKM_DES_CBC_PAD));
        keyMechanisms.add(new KeyMechanism("DES ECB", PKCS11Constants.CKM_DES_ECB));
        keyMechanisms.add(new KeyMechanism("DES3 CBC", PKCS11Constants.CKM_DES3_CBC));
        keyMechanisms.add(new KeyMechanism("DES3 CBC PADDING", PKCS11Constants.CKM_DES3_CBC_PAD));
        keyMechanisms.add(new KeyMechanism("DES3 ECB", PKCS11Constants.CKM_DES_ECB));
        return keyMechanisms;
    }

    public static List<KeyMechanism> keyMechanismsAsymmetric() {
        List<KeyMechanism> keyMechanisms = new ArrayList<>();
        keyMechanisms.add(new KeyMechanism("RSA PKCS", PKCS11Constants.CKM_RSA_PKCS));
        return keyMechanisms;
    }
    // key mechanism for signature
    public static List<KeyMechanism> keyMechanismsSignature() {
        List<KeyMechanism> keyMechanisms = new ArrayList<>();
        keyMechanisms.add(new KeyMechanism("DSA SHA1", PKCS11Constants.CKM_DSA_SHA1));
//        keyMechanisms.add(new KeyMechanism("DSA SHA256", PKCS11Constants.CKM_DSA_SHA256));
//        keyMechanisms.add(new KeyMechanism("DSA SHA512", PKCS11Constants.CKM_DSA_SHA512));
        keyMechanisms.add(new KeyMechanism("ECDSA SHA1", PKCS11Constants.CKM_ECDSA_SHA1));
        keyMechanisms.add(new KeyMechanism("RSA SHA1 PKCS", PKCS11Constants.CKM_SHA1_RSA_PKCS));

        return keyMechanisms;
    }
}
