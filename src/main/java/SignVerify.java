import helper.Convert;
import helper.Hsm;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class SignVerify {
    public static void main(String[] args) throws IOException {
        Hsm hsm = Hsm.getInstance();
        hsm.slot(5);
        hsm.authentication(PKCS11Constants.CKU_USER, "987654321");

        long keyPairGen = PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
        long key = PKCS11Constants.CKM_SHA1_RSA_PKCS;

        hsm.setMechanismKeyGen(keyPairGen);
        hsm.setMechanismCrypt(key);

        System.out.println("=================================================");
        System.out.print("Input text: ");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String text = reader.readLine();
        System.out.println("=================================================");

        hsm.signature(text.getBytes(), false, true, keyPairGen);
        byte[] signatureByte = hsm.getSignatureByte();
        System.out.println("Signature: "+Convert.byteArrayToHex(signatureByte));
        System.out.println("=================================================");

        hsm.verify(text.getBytes(), signatureByte, false, true, keyPairGen);
        hsm.signOut();
    }
}
