import helper.Convert;
import helper.Hsm;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class Sign {
    public static void main(String[] args) throws IOException {
        Hsm hsm = Hsm.getInstance();
        hsm.slot(5);
        hsm.authentication(PKCS11Constants.CKU_USER, "987654321");

        long keyGenPair = PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
        long key = PKCS11Constants.CKM_SHA1_RSA_PKCS;

        hsm.setMechanismKeyGen(keyGenPair);
        hsm.setMechanismCrypt(key);

        System.out.println("===========================================================");
        System.out.print("Input sign text: ");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String plaintText = reader.readLine();
        System.out.println("===========================================================");

        hsm.signature(plaintText.getBytes(), false, true, keyGenPair);
        System.out.println("key pub: " + hsm.getKeyPublic());
        System.out.println("key priv: " + hsm.getKeyPrivate());
        System.out.println("signature: " + Convert.byteArrayToHex(hsm.getSignatureByte()));
        System.out.println("===========================================================");

        hsm.signOut();
    }
}
