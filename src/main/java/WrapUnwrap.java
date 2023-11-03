import helper.Convert;
import helper.Hsm;
import org.xipki.pkcs11.wrapper.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class WrapUnwrap {

    public static void main(String[] args) throws IOException {
        Hsm hsm = Hsm.getInstance();
        hsm.slot(5);
        hsm.authentication(PKCS11Constants.CKU_USER, "987654321");

        long keyGen = PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
        long key = PKCS11Constants.CKM_AES_ECB;

        hsm.setMechanismKeyGen(keyGen);
        hsm.setMechanismCrypt(key);

        // find object
        long keyHandle = hsm.findObject("AES68");
        System.out.println("key handle: " + keyHandle);

        System.out.println("=====================================================================");
        // wrapKey
        byte[] wrap = hsm.wrap(keyHandle, false, true, keyGen, false);
        String s = Convert.byteArrayToHex(wrap);
        System.out.println("wrap hex: "+s);

        File outFile = new File("wrapkey");
        Files.write(outFile.toPath(), wrap);

        long unwrapKey = hsm.unwrap(wrap, keyHandle, false, "aes-private-test-a", false, false);
        System.out.println("unwrap key: " +unwrapKey);

        hsm.signOut();
    }
}
