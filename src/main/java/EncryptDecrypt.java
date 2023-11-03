import helper.Hsm;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Exception;

import javax.crypto.BadPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class EncryptDecrypt {
    public static void main(String[] args) throws IOException, PKCS11Exception, BadPaddingException {
        Hsm hsm = Hsm.getInstance();
        hsm.slot(5);
        hsm.authentication(PKCS11Constants.CKU_USER, "987654321");
        long keyPairGen = PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
        long keyCrypto = PKCS11Constants.CKM_RSA_PKCS;

        hsm.setMechanismKeyGen(keyPairGen);
        hsm.setMechanismCrypt(keyCrypto);

        System.out.println("===========================================================");
        System.out.print("Input plaintext: ");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String plaintText = reader.readLine();
        System.out.println("===========================================================");

        hsm.encryptDecrypt(false, true, keyPairGen, false, plaintText, 0);
        System.out.println("===========================================================");
        hsm.signOut();
    }
}
