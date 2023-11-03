package utils;

import java.util.ArrayList;
import java.util.List;

public class Const {
    public static List<String> keyGen() {
        List<String> key = new ArrayList<>();
        key.add("AES68");
        key.add("AES_GEN");
        key.add("DES68");
        key.add("DES2_GEN");
        key.add("rsa-pub-4096");
        key.add("rsa-priv-4096");
        return key;
    }

    public static List<String> keySignVerify() {
        List<String> key = new ArrayList<>();
        key.add("rsa-pub-4096");
        key.add("rsa-priv-4096");
        key.add("ec-pb-256");
        key.add("ec-pr-256");
        return key;
    }

    public static List<String> keyCertificate() {
        List<String> key = new ArrayList<>();
        key.add("RSA-PUBLIC");
        key.add("RSA-PRIVATE");
        key.add("EC_PUB");
        key.add("EC_PRV");
        return key;
    }
}
