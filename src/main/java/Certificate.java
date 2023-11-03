import helper.Hsm;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

import java.io.File;
import java.net.URL;

public class Certificate {
    public static void main(String[] args) {
        Hsm hsm = Hsm.getInstance();
        hsm.slot(5);
        hsm.authentication(PKCS11Constants.CKU_USER, "987654321");

//        long keyGen = PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
//        long key = PKCS11Constants.CKM_RSA_X_509;

//        hsm.setMechanismKeyGen(keyGen);
//        hsm.setMechanismCrypt(key);

        hsm.certificate("Afif","CODER","Kudus","ID","Central Java","Pura PST CA" );

        File file = new File("cert.crt");
        File file1 = new File("cert1.crt");
        hsm.verifyCertificate(file, file1);
        hsm.signOut();
    }
}
