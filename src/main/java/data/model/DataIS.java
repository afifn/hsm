package data.model;

import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CardVerifiableCertificate;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

public class DataIS {
    private CardVerifiableCertificate cert;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private CVCPrincipal cvcPrincipal;
    private Date effDate;
    private Date expDate;

    public DataIS(CardVerifiableCertificate cert, PublicKey publicKey, PrivateKey privateKey, CVCPrincipal cvcPrincipal, Date effDate, Date expDate) {
        this.cert = cert;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.cvcPrincipal = cvcPrincipal;
        this.effDate = effDate;
        this.expDate = expDate;
    }

    public CardVerifiableCertificate getCert() {
        return cert;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public CVCPrincipal getCvcPrincipal() {
        return cvcPrincipal;
    }

    public Date getEffDate() {
        return effDate;
    }

    public Date getExpDate() {
        return expDate;
    }
}
