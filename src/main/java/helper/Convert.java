package helper;

import java.nio.charset.StandardCharsets;

public class Convert {
    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String string2Hex(String text) {
        byte[] byteData = text.getBytes(StandardCharsets.UTF_8);
        StringBuilder hexString = new StringBuilder();
        for (byte b : byteData) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }

    public static byte[] padding(String dataToEncrypt, int sizelength) {
        // Konversi string ke bentuk hexstring
        byte[] utf8Bytes = dataToEncrypt.getBytes(StandardCharsets.UTF_8);
        StringBuilder hexString = new StringBuilder();

        for (byte b : utf8Bytes) {
            hexString.append(String.format("%02x", b));
        }

        // Tambahkan padding '00' jika perlu
        if (hexString.length() % (sizelength * 2) != 0) {
            int paddingLength = sizelength * 2 - (hexString.length() % (sizelength * 2));
            hexString.append("00".repeat(paddingLength / 2));
        }

        // Konversi hexstring ke byte array
        byte[] resultBytes = new byte[hexString.length() / 2];

        for (int i = 0; i < hexString.length(); i += 2) {
            String byteStr = hexString.substring(i, i + 2);
            resultBytes[i / 2] = (byte) Integer.parseInt(byteStr, 16);
        }

        return resultBytes;
    }

}
