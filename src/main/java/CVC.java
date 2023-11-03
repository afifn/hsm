import helper.Hsm;
import org.ejbca.cvc.exception.ConstructionException;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Exception;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;

public class CVC {
    public static void main(String[] args) {
        Hsm hsm = Hsm.getInstance();
        hsm.slot(5);
        hsm.authentication(PKCS11Constants.CKU_USER, "987654321");

//        try {
//            hsm.getKeyPrivateFromHSM("DES_M");
//        } catch (PKCS11Exception | NoSuchAlgorithmException | NoSuchProviderException |
//                 InvalidAlgorithmParameterException | IOException e) {
//            throw new RuntimeException(e);
//        }
        try {
            hsm.createCVC();
        } catch (PKCS11Exception | CertificateEncodingException | IOException | NoSuchAlgorithmException |
                 SignatureException | InvalidKeyException | ConstructionException e) {
            throw new RuntimeException(e);
        }
        hsm.signOut();
    }
}

