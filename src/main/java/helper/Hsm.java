package helper;

import data.model.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.ejbca.cvc.*;
import org.ejbca.cvc.exception.ConstructionException;
import org.jmrtd.cert.CVCAuthorizationTemplate;
import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CardVerifiableCertificate;
import org.xipki.pkcs11.wrapper.*;
import utils.Print;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

import static helper.Convert.byteArrayToHex;
import static helper.Convert.padding;

public class Hsm {
    private static Hsm instance;
    private final PKCS11Module module;
    private Slot slot;
    private Session session;
    private Mechanism mechanismKeyGen;
    private Mechanism mechanismCrypt;

    private byte[] signatureByte;
    private String signatureString;
    private long keyPublic;
    private long keyPrivate;

    public static synchronized Hsm getInstance() {
        if (instance == null) {
            instance = new Hsm();
        }
        return instance;
    }

    private Hsm() {
        try {
            module = PKCS11Module.getInstance("D:\\INTELIJ\\HSM\\src\\main\\resources\\cryptoki.dll");
            module.initialize();
        } catch (IOException | PKCS11Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void slot(int index) {
        try {
            Slot[] slotList = module.getSlotList(true);
            slot = slotList[index];
        } catch (PKCS11Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void authentication(long ckUser, String password) {
        try {
            Token token = slot.getToken();
            session = token.openSession(true);
            session.login(ckUser, password.toCharArray());
        } catch (PKCS11Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void auth(long ckUser, String password) throws PKCS11Exception {
        Token token = slot.getToken();
        session = token.openSession(true);
        session.login(ckUser, password.toCharArray());
    }

    public void setMechanismKeyGen(long mechanism) {
        mechanismKeyGen = new Mechanism(mechanism);
    }

    public void setMechanismCrypt(long mechanism) {
        mechanismCrypt = new Mechanism(mechanism);
    }

    private AttributeVector setAttributeVector(long CKM, boolean token, boolean pub) {
        AttributeVector vector = new AttributeVector();
        BigInteger bigInteger = new BigInteger(new byte[]{1, 0, 1});

        if (CKM == PKCS11Constants.CKM_AES_KEY_GEN) {
            vector.class_(PKCS11Constants.CKO_SECRET_KEY);
            vector.token(token);
            vector.label("AES");
            vector.valueLen(256 / 8);
            vector.sensitive(true);
            vector.verify(true);
            vector.sign(true);
            vector.encrypt(true);
            vector.decrypt(true);
            println("==========\nAES\n==========");
        } else if (CKM == PKCS11Constants.CKM_DES_KEY_GEN) {
            vector.class_(PKCS11Constants.CKO_SECRET_KEY);
            vector.token(token);
            vector.label("DES");
            vector.valueLen(8);
            vector.sensitive(false);
            vector.verify(true);
            vector.sign(true);
            vector.encrypt(true);
            vector.decrypt(true);
            println("==========\nDES\n==========");
        } else if (CKM == PKCS11Constants.CKM_DES2_KEY_GEN) {
            vector.class_(PKCS11Constants.CKO_SECRET_KEY);
            vector.token(token);
            vector.label("DES2");
            vector.valueLen(16);
            vector.keyType();
            vector.sensitive(false);
            vector.sign(true);
            vector.encrypt(true);
            vector.decrypt(true);
            vector.verify(true);
            println("==========\nDES2\n==========");
        } else if (CKM == PKCS11Constants.CKM_DES3_KEY_GEN) {
            vector.class_(PKCS11Constants.CKO_SECRET_KEY);
            vector.token(token);
            vector.label("DES3");
            vector.valueLen(24);
            vector.sensitive(true);
            vector.sign(true);
            vector.encrypt(true);
            vector.decrypt(true);
            println("==========\nDES3\n==========");
        } else if (CKM == PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN) {
            if (pub) {
                vector.class_(PKCS11Constants.CKO_PUBLIC_KEY);
                vector.token(token);
                vector.label("RSA Pub");
                vector.publicExponent(bigInteger);
                vector.modulusBits(2024);
                vector.verify(true);
            } else {
                vector.class_(PKCS11Constants.CKO_PRIVATE_KEY);
                vector.token(token);
                vector.label("RSA Priv");
                vector.sign(true);
            }
        } else if (CKM == PKCS11Constants.CKM_EC_KEY_PAIR_GEN) {
            if (pub) {
                vector.class_(PKCS11Constants.CKO_PUBLIC_KEY);
                vector.token(token);
                vector.label("EC Pub");
                vector.publicExponent(bigInteger);
                vector.modulusBits(1024);
                vector.wrap(false);
                vector.verify(true);
                vector.ecParams();
            } else {
                vector.class_(PKCS11Constants.CKO_PRIVATE_KEY);
                vector.token(token);
                vector.label("EC Priv");
                vector.unwrap(false);
                vector.sign(true);
            }
        }
        return vector;
    }

    public String encrypt(String plainText, int length, String findKey) throws PKCS11Exception {

        String resultString;

        long keyHandle = findObject(findKey);
        session.encryptInit(mechanismCrypt, keyHandle);
        byte[] resultPadding = padding(plainText, length);
        byte[] enc = session.encrypt(resultPadding);
        resultString = Convert.byteArrayToHex(enc);

        return resultString;
    }

    public String decrypt(String cipher, String keyGen) throws PKCS11Exception {
        byte[] cipherByte = Convert.hexStringToByteArray(cipher);
        long keyHandle = findObject(keyGen);
        session.decryptInit(mechanismCrypt, keyHandle);
        byte[] decrypt = session.decrypt(cipherByte);
        return new String(decrypt);
    }

    public void encryptDecrypt(boolean symmetric, boolean asymmetric, long mechanismGen, boolean token, String plaintext, int length) {
        AttributeVector pubTemplate = setAttributeVector(mechanismGen, token, asymmetric);
        AttributeVector privateTemplate = setAttributeVector(mechanismGen, token, !asymmetric);

        String byte2Hex;
        try {
            if (symmetric) { //3DES, AES, DES, RC
                long keyHandle = session.generateKey(mechanismKeyGen, pubTemplate);
                session.encryptInit(mechanismCrypt, keyHandle);

                byte[] resultPadding = padding(plaintext, length);
                System.out.println(byteArrayToHex(resultPadding));

                byte[] encrypt = session.encrypt(resultPadding);

                byte2Hex = Convert.byteArrayToHex(encrypt);
                System.out.println("result encrypt: " + byte2Hex);

                // decrypt
                session.decryptInit(mechanismCrypt, keyHandle);
                byte[] decrypt = session.decrypt(encrypt);
                String decryptStr = new String(decrypt);
                System.out.println("result decrypt: " + decryptStr.trim());
            } else { // RSA, EC
                PKCS11KeyPair keyPair = session.generateKeyPair(mechanismKeyGen, new KeyPairTemplate(privateTemplate, pubTemplate));
                long publicKey = keyPair.getPublicKey();
                session.encryptInit(mechanismCrypt, publicKey);
                byte[] encrypt = session.encrypt(plaintext.getBytes(StandardCharsets.UTF_8));

                byte2Hex = Convert.byteArrayToHex(encrypt);
                System.out.println("result encrypt: " + byte2Hex);

                // decrypt
                long privateKey = keyPair.getPrivateKey();
                session.decryptInit(mechanismCrypt, privateKey);
                byte[] decrypt = session.decrypt(encrypt);
                System.out.println("result decrypt: " + new String(decrypt).trim());
            }
        } catch (PKCS11Exception e) {
            throw new RuntimeException(e);
        }
    }

    public long findObject(String label) {
        AttributeVector attributeVector = new AttributeVector();
        attributeVector.label(label);
        try {
            session.findObjectsInit(attributeVector);
            long[] objects = session.findObjects(1);
            long key = objects[0];
            session.findObjectsFinal();
            return key;
        } catch (PKCS11Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String signature(String data, String mechanism) throws PKCS11Exception {
        long key = findObject(mechanism);
        Print.printLn(mechanismCrypt);
        session.signInit(mechanismCrypt, key);
        byte[] sign = session.sign(data.getBytes());
        return byteArrayToHex(sign);
    }

    public void signature(byte[] data, boolean symmetric, boolean asymmetric, long mechanism) {
        AttributeVector pubTemplate = setAttributeVector(mechanism, false, asymmetric);
        AttributeVector privateTemplate = setAttributeVector(mechanism, false, !asymmetric);
        try {
            if (symmetric) {
                long keyHandle = session.generateKey(mechanismKeyGen, pubTemplate);
                println(keyHandle);
                session.signInit(mechanismCrypt, keyHandle);
                byte[] sign = session.sign(data);
                println("signature: " + sign);
            } else {
                PKCS11KeyPair keyPair = session.generateKeyPair(mechanismKeyGen, new KeyPairTemplate(privateTemplate, pubTemplate));
                keyPrivate = keyPair.getPrivateKey();
                keyPublic = keyPair.getPublicKey();

                session.signInit(mechanismCrypt, keyPrivate);
                byte[] sign = session.sign(data);
                setSignatureByte(sign);

//                verify(data, Convert.byteArrayToHex(sign), false, true, mechanism, keyPublic);
            }
        } catch (PKCS11Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void verify(String data, String signature, String mechanism) throws PKCS11Exception {
        long key = findObject(mechanism);
        byte[] dataSign = Convert.hexStringToByteArray(signature);

        session.verifyInit(mechanismCrypt, key);
        session.verify(data.getBytes(), dataSign);
    }

    public void verify(byte[] data, byte[] sign, boolean symmetric, boolean asymmetric, long mechanism) {
        AttributeVector pubTemplate = setAttributeVector(mechanism, false, asymmetric);
        AttributeVector privateTemplate = setAttributeVector(mechanism, false, !asymmetric);

        try {
            if (symmetric) {
                long key = session.generateKey(mechanismKeyGen, pubTemplate);
                session.verifyInit(mechanismCrypt, key);

                session.verify(data, sign);
            } else {
                session.verifyInit(mechanismCrypt, keyPublic);
                session.verify(data, sign);

                println("verify: success");
            }
        } catch (PKCS11Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void verify(byte[] data, String sign, boolean symmetric, boolean asymmetric, long mechanism, long keyPublic) {
        AttributeVector pubTemplate = setAttributeVector(mechanism, false, asymmetric);
        AttributeVector privateTemplate = setAttributeVector(mechanism, false, !asymmetric);

        byte[] signature = Convert.hexStringToByteArray(sign);
        try {
            if (symmetric) {
                long key = session.generateKey(mechanismKeyGen, pubTemplate);
                session.verifyInit(mechanismCrypt, key);

                session.verify(data, signature);
            } else {
                session.verifyInit(mechanismCrypt, keyPublic);
                session.verify(data, signature);

                println("verify: success");
            }
        } catch (PKCS11Exception e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * KeyTemplateObject = key yang digunakan untuk encrypt key yang diperoleh dari HSM
     */
    public byte[] wrap(long keyTemplateObject, boolean symmetric, boolean asymmetric, long CKM, boolean token) {
        AttributeVector pubAttr = setAttributeVector(CKM, token, asymmetric);
        AttributeVector privAttr = setAttributeVector(CKM, token, !asymmetric);
        byte[] bytes;
        try {
            if (symmetric) {
                long key = session.generateKey(mechanismKeyGen, pubAttr);
                bytes = session.wrapKey(mechanismCrypt, keyTemplateObject, key);
            } else {
                PKCS11KeyPair key = session.generateKeyPair(mechanismKeyGen, new KeyPairTemplate(privAttr, pubAttr));
                long publicKey = key.getPublicKey();
                long privateKey = key.getPrivateKey();

                bytes = session.wrapKey(mechanismCrypt, keyTemplateObject, privateKey);
            }
            return bytes;
        } catch (PKCS11Exception e) {
            throw new RuntimeException(e);
        }
    }

    public long unwrap(byte[] data, long keyTemplateObject, boolean symmetric, String label, boolean isPublic, boolean token) {
        AttributeVector vector = new AttributeVector();
        if (symmetric) {
            vector.class_(PKCS11Constants.CKO_SECRET_KEY);
            vector.label(label);
            vector.token(token);
        } else {
            if (isPublic) {
                vector.class_(PKCS11Constants.CKO_PUBLIC_KEY);
                vector.label(label);
                vector.token(token);
            } else {
                vector.class_(PKCS11Constants.CKO_PRIVATE_KEY);
                vector.label(label);
                vector.token(token);
            }
        }
        try {
            return session.unwrapKey(mechanismCrypt, keyTemplateObject, data, vector);
        } catch (PKCS11Exception e) {
            throw new RuntimeException(e);
        }
    }

    // certificate
    private X500NameBuilder getX509SubjectCertificate(FormCert cert) {
        X500NameBuilder nameBuilder = new X500NameBuilder(RFC4519Style.INSTANCE);
        nameBuilder.addRDN(RFC4519Style.c, cert.getCountry());
        nameBuilder.addRDN(RFC4519Style.cn, cert.getCn());
        nameBuilder.addRDN(RFC4519Style.o, cert.getOrganization());
        nameBuilder.addRDN(RFC4519Style.l, cert.getLocation());
        nameBuilder.addRDN(RFC4519Style.st, cert.getState());
        return nameBuilder;
    }

    public void getKeyPrivateFromHSM(String pr) throws PKCS11Exception, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        PrivateKey privateKey = null;
        long keyHandle = findObject(pr);
        AttributeVector attrValues = session.getAttrValues(keyHandle, PKCS11Constants.CKA_VALUE);

        println(attrValues.valueLen());
        if (pr.toLowerCase().startsWith("rsa")) {

            AttributeVector privateModulus = session.getAttrValues(keyHandle, PKCS11Constants.CKA_MODULUS);
            AttributeVector privateExponent = session.getAttrValues(keyHandle, PKCS11Constants.CKA_PRIVATE_EXPONENT);

            privateKey = getPrivateKey(privateModulus.modulus(), privateExponent.privateExponent());
        } else if (pr.toLowerCase().startsWith("ec")) {
            AttributeVector privateM = session.getAttrValues(keyHandle, PKCS11Constants.CKA_EC_PARAMS);
            byte[] ecParams = privateM.ecParams();
            ASN1Primitive asn1Primitive = ASN1Primitive.fromByteArray(ecParams);
            println(asn1Primitive);
            ASN1ObjectIdentifier ecId = new ASN1ObjectIdentifier(asn1Primitive.toString());
            X9ECParameters x9ECParameters = CustomNamedCurves.getByOID(ecId);

            EllipticCurve curve = new EllipticCurve(new ECFieldFp(x9ECParameters.getCurve().getField().getCharacteristic()), x9ECParameters.getCurve().getA().toBigInteger(), x9ECParameters.getCurve().getB().toBigInteger());
            ECPoint g = new ECPoint(x9ECParameters.getG().getAffineXCoord().toBigInteger(), x9ECParameters.getG().getAffineYCoord().toBigInteger());
            BigInteger n = x9ECParameters.getN();
            int h = x9ECParameters.getH().intValue();
            ECParameterSpec ecParameterSpec = new ECParameterSpec(curve, g, n, h);
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");

            try {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Convert.hexStringToByteArray("11223344556677889900112233445566"));
                PrivateKey key = keyFactory.generatePrivate(keySpec);
                println(key);
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        }

    }

    public void certificate(String pub, String priv, FormCert formCert) throws PKCS11Exception, OperatorCreationException, CertificateException, IOException, ParseException {
        long keyHandleRSAPublic = findObject(pub);
        long keyHandleRSAPrivate = findObject(priv);

        AttributeVector privateModulus = session.getAttrValues(keyHandleRSAPrivate, PKCS11Constants.CKA_MODULUS);
        AttributeVector privateExponent = session.getAttrValues(keyHandleRSAPrivate, PKCS11Constants.CKA_PRIVATE_EXPONENT);

        AttributeVector publicModulus = session.getAttrValues(keyHandleRSAPublic, PKCS11Constants.CKA_MODULUS);
        AttributeVector publicExponent = session.getAttrValues(keyHandleRSAPublic, PKCS11Constants.CKA_PUBLIC_EXPONENT);
        Print.printLn(privateExponent + " = " + publicExponent);

        PrivateKey rsaPrivateKey = getPrivateKey(privateModulus.modulus(), privateExponent.privateExponent());
        PublicKey rsaPublicKey = getPublicKey(publicModulus.modulus(), publicExponent.publicExponent());
        String algorithm = signatureAlgorithm(rsaPublicKey);

        SimpleDateFormat formatter = new SimpleDateFormat("dd MMM yyyy", new Locale("id", "ID"));
        Date beginUp = formatter.parse(formCert.getStDate());
        Date endUp = formatter.parse(formCert.getEnDate());
        Date startDate = new Date(beginUp.getTime());
        Date endDate = new Date(endUp.getTime());

        X500Name issuer = new X500Name("CN=" + formCert.getIssuer());
        X500NameBuilder nameBuilder = getX509SubjectCertificate(formCert);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, new BigInteger(String.valueOf(System.currentTimeMillis())), startDate, endDate, nameBuilder.build(), rsaPublicKey);
        ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build(rsaPrivateKey);
        X509CertificateHolder certificate = certBuilder.build(contentSigner);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certificate);
        println("\n===============================================================\n");

        byte[] encoded = certificate.getEncoded();
        String pemFormat = createPEMFormat(encoded);
        println(pemFormat);

        File outFile = new File("cert.crt");
        FileOutputStream fos = new FileOutputStream(outFile);
        fos.write(cert.getEncoded());
        fos.close();
//            Files.write(outFile.toPath(), encoded);

        FormCert formCert1 = new FormCert(formCert.getCn(), formCert.getIssuer(), formCert.getOrganization(), formCert.getCountry(), formCert.getState(), formCert.getLocation());
        X500NameBuilder nameBuilder1 = getX509SubjectCertificate(formCert1);

        X500Name subject = new X500Name("CN=" + formCert.getIssuer());
        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                cert, new BigInteger(String.valueOf(System.currentTimeMillis())), startDate, endDate, nameBuilder1.build(), cert.getPublicKey());
        ContentSigner contentSigner1 = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(rsaPrivateKey);
        X509CertificateHolder certificate1 = certificateBuilder.build(contentSigner1);
        X509Certificate cert1 = new JcaX509CertificateConverter().getCertificate(certificate1);

        File outFile1 = new File("cert1.crt");
        FileOutputStream fos1 = new FileOutputStream(outFile1);
        fos1.write(cert1.getEncoded());
        fos1.close();
    }
    public void certificate(String cn, String organization, String location, String country, String state, String sIssuer) {
        try {
            long keyHandleRSAPrivate = findObject("RSA-PRIVATE");
            long keyHandleRSAPublic = findObject("RSA-PUBLIC");
            FormCert formCert = new FormCert(sIssuer, cn, organization, country, state, location);

            AttributeVector privateModulus = session.getAttrValues(keyHandleRSAPrivate, PKCS11Constants.CKA_MODULUS);
            AttributeVector privateExponent = session.getAttrValues(keyHandleRSAPrivate, PKCS11Constants.CKA_PRIVATE_EXPONENT);

            AttributeVector publicModulus = session.getAttrValues(keyHandleRSAPublic, PKCS11Constants.CKA_MODULUS);
            AttributeVector publicExponent = session.getAttrValues(keyHandleRSAPublic, PKCS11Constants.CKA_PUBLIC_EXPONENT);

            PrivateKey rsaPrivateKey = getPrivateKey(privateModulus.modulus(), privateExponent.privateExponent());
            PublicKey rsaPublicKey = getPublicKey(publicModulus.modulus(), publicExponent.publicExponent());

            Date startDate = new Date(System.currentTimeMillis());
            Date endDate = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

            X500Name issuer = new X500Name("CN=" + sIssuer);
            X500NameBuilder nameBuilder = getX509SubjectCertificate(formCert);

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer, new BigInteger(String.valueOf(System.currentTimeMillis())), startDate, endDate, nameBuilder.build(), rsaPublicKey);
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(rsaPrivateKey);
            X509CertificateHolder certificate = certBuilder.build(contentSigner);
            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certificate);
            println("\n===============================================================\n");

            byte[] encoded = certificate.getEncoded();
            String pemFormat = createPEMFormat(encoded);
            println(pemFormat);

            File outFile = new File("cert.crt");
            FileOutputStream fos = new FileOutputStream(outFile);
            fos.write(cert.getEncoded());
            fos.close();
//            Files.write(outFile.toPath(), encoded);

            X500Name subject = new X500Name("CN=AHO1");
            JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    cert, new BigInteger(String.valueOf(System.currentTimeMillis())), startDate, endDate, subject, cert.getPublicKey());
            ContentSigner contentSigner1 = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(rsaPrivateKey);
            X509CertificateHolder certificate1 = certificateBuilder.build(contentSigner1);
            X509Certificate cert1 = new JcaX509CertificateConverter().getCertificate(certificate1);

            File outFile1 = new File("cert1.crt");
            FileOutputStream fos1 = new FileOutputStream(outFile1);
            fos1.write(cert1.getEncoded());
            fos1.close();
        } catch (IOException | OperatorCreationException | CertificateException | PKCS11Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String signatureAlgorithm(PublicKey pub) {
        switch (pub.getAlgorithm()) {
            case "EC":
                EllipticCurve curve = ((ECPublicKey) pub).getParams().getCurve();
                switch (curve.getField().getFieldSize()) {
                    case 224:
                    case 256:
                        return "SHA256withECDSA";
                    case 384:
                        return "SHA384withECDSA";
                    case 521:
                        return "SHA512withECDSA";
                    default:
                        throw new IllegalArgumentException("unknown elliptic curve: " + curve);
                }
            case "RSA":
                return "SHA256WithRSAEncryption";
            default:
                throw new UnsupportedOperationException("unsupported private key algorithm: " + pub.getAlgorithm());
        }
    }

    public void verifyCertificate(File certificate, File certificate2) {
        try {
            println("\n===============================================================");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream(certificate);
            X509Certificate trustCertificate = (X509Certificate) certificateFactory.generateCertificate(fis);

            println("algo: " + trustCertificate.getSigAlgName());
            trustCertificate.getPublicKey();

            FileInputStream fis2 = new FileInputStream(certificate2);
            X509Certificate verifyCertificate = (X509Certificate) certificateFactory.generateCertificate(fis2);

            verifyCertificate.verify(trustCertificate.getPublicKey());
            println("success verify certificate");
            println("===============================================================");
        } catch (FileNotFoundException | CertificateException | NoSuchAlgorithmException | SignatureException |
                 InvalidKeyException | NoSuchProviderException e) {
            println(e.getMessage());
            println("===============================================================");
        }
    }

    public void verifyCertificates(File certificate, File certificate2) throws CertificateException, FileNotFoundException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        println("\n===============================================================");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(certificate);
        X509Certificate trustCertificate = (X509Certificate) certificateFactory.generateCertificate(fis);

        println("algo: " + trustCertificate.getSigAlgName());
        trustCertificate.getPublicKey();

        FileInputStream fis2 = new FileInputStream(certificate2);
        X509Certificate verifyCertificate = (X509Certificate) certificateFactory.generateCertificate(fis2);

        verifyCertificate.verify(trustCertificate.getPublicKey());
    }

    public CertificateData getExtractCertificate(File certificate) throws CertificateException, FileNotFoundException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(certificate);
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(fis);
        SimpleDateFormat sf = new SimpleDateFormat("dd MMM yyyy");
        Date notAfter = cert.getNotAfter();
        Date notBefore = cert.getNotBefore();

        String stDate = sf.format(notBefore);
        String enDate = sf.format(notAfter);
        String sigAlgName = cert.getSigAlgName();

        X500Name x500Name = new JcaX509CertificateHolder(cert).getSubject();
        RDN[] rdNs = x500Name.getRDNs();
        for (RDN na : rdNs) {
            String s = IETFUtils.valueToString(na.getFirst().getValue());
            Print.printLn(s);
        }
        RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
        String compName = IETFUtils.valueToString(cn.getFirst().getValue());

        return new CertificateData(compName, "", stDate, enDate, sigAlgName);
    }

    private PublicKey getPublicKey(BigInteger modulus, BigInteger publicExponent) {
        try {
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private PrivateKey getPrivateKey(BigInteger modulus, BigInteger privateExponent) {
        try {
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private String createPEMFormat(byte[] data) {
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        final PrintStream ps = new PrintStream(bos);
        ps.println("-----BEGIN NEW CERTIFICATE REQUEST-----");
        ps.println(Base64.getMimeEncoder().encodeToString(data));
        ps.println("-----END NEW CERTIFICATE REQUEST-----");
        return bos.toString();
    }


    private DataCV dataCV;
    public void createCVC() throws PKCS11Exception, IOException, CertificateEncodingException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, ConstructionException {
        CVCPrincipal authorityPrincipalCV = new CVCPrincipal("IDPURAEPPCV001");
        CVCPrincipal holderPrincipalCV = authorityPrincipalCV;
        CVCAuthorizationTemplate.Role role = CVCAuthorizationTemplate.Role.CVCA;
        CVCAuthorizationTemplate.Permission permissionCV;
        permissionCV = CVCAuthorizationTemplate.Permission.READ_ACCESS_DG3_AND_DG4;

        String method  = "SHA256WITHRSA";
        long keyHandleRSAPrivate = findObject("RSA-PRIVATE");
        long keyHandleRSAPublic = findObject("RSA-PUBLIC");

        AttributeVector privateModulus = session.getAttrValues(keyHandleRSAPrivate, PKCS11Constants.CKA_MODULUS);
        AttributeVector privateExponent = session.getAttrValues(keyHandleRSAPrivate, PKCS11Constants.CKA_PRIVATE_EXPONENT);

        AttributeVector publicModulus = session.getAttrValues(keyHandleRSAPublic, PKCS11Constants.CKA_MODULUS);
        AttributeVector publicExponent = session.getAttrValues(keyHandleRSAPublic, PKCS11Constants.CKA_PUBLIC_EXPONENT);

        Date notBeforeDV = new Date(System.currentTimeMillis());
        Date notAfterDV;
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(notBeforeDV);
        calendar.add(Calendar.YEAR, 3);
        notAfterDV = calendar.getTime();

        PrivateKey rsaPrivateKey = getPrivateKey(privateModulus.modulus(), privateExponent.privateExponent());
        PublicKey rsaPublicKey = getPublicKey(publicModulus.modulus(), publicExponent.publicExponent());
/*        ==================*/
        CAReferenceField authorityReference = new CAReferenceField(authorityPrincipalCV.getCountry().toAlpha2Code(), authorityPrincipalCV.getMnemonic(), authorityPrincipalCV.getSeqNumber());
        HolderReferenceField holderReferenceField = new HolderReferenceField(authorityPrincipalCV.getCountry().toAlpha2Code(), authorityPrincipalCV.getMnemonic(), authorityPrincipalCV.getSeqNumber());

        AuthorizationRoleEnum authorizationRoleEnum = AuthorizationRoleEnum.CVCA;
        AccessRightEnum accessRight = AccessRightEnum.READ_ACCESS_DG3_AND_DG4;

        CVCertificateBody cvCertificateBody = new CVCertificateBody(authorityReference, org.ejbca.cvc.KeyFactory.createInstance(rsaPublicKey, method, authorizationRoleEnum ), holderReferenceField, authorizationRoleEnum, accessRight, notBeforeDV, notAfterDV);

        Signature signature = Signature.getInstance(method);
        signature.initSign(rsaPrivateKey);
        signature.update(cvCertificateBody.getDEREncoded());
        byte[] sign1 = signature.sign();

        CVCertificate certificate = new CVCertificate(cvCertificateBody);
        certificate.setSignature(sign1);
        certificate.getTBS();

        Print.printLn(certificate);

/*        ==================*/

        CardVerifiableCertificate cv = new CardVerifiableCertificate(authorityPrincipalCV, holderPrincipalCV, rsaPublicKey, method, notBeforeDV, notAfterDV, role, permissionCV, sign1);
        File outFile1 = new File("cv-"+authorityPrincipalCV.getName()+".cvcert");
        FileOutputStream fos1 = new FileOutputStream(outFile1);
        fos1.write(cv.getEncoded());
        fos1.close();

        dataCV = new DataCV(cv, rsaPublicKey, rsaPrivateKey, authorityPrincipalCV, notBeforeDV, notAfterDV, method);

        createDV();
    }



    DataDV dataDV;
    public void createDV() throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException, ConstructionException, CertificateEncodingException {
        println("\n============================================\n");
        KeyPair keyPair = Generate.generaterKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        CVCPrincipal holderReferenceDV = new CVCPrincipal("IDPURAEPPDV001");

        Date notBeforeDV = new Date(System.currentTimeMillis());
        Date notAfter;
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(notBeforeDV);
        calendar.add(Calendar.YEAR, 3);
        calendar.add(Calendar.MONTH, -1);
        notAfter = calendar.getTime();

        CVCPrincipal authorityPrincipalDV = dataCV.getCvcPrincipal();
        CVCAuthorizationTemplate.Role roleDV = CVCAuthorizationTemplate.Role.DV_F;
        CVCAuthorizationTemplate.Permission permissionDV = CVCAuthorizationTemplate.Permission.READ_ACCESS_DG3_AND_DG4;

        CAReferenceField caReferenceFieldDV = new CAReferenceField(authorityPrincipalDV.getCountry().toAlpha2Code(), authorityPrincipalDV.getMnemonic(), authorityPrincipalDV.getSeqNumber());
        HolderReferenceField holderReferenceFieldDV = new HolderReferenceField(holderReferenceDV.getCountry().toAlpha2Code(), holderReferenceDV.getMnemonic(), holderReferenceDV.getSeqNumber());

        AuthorizationRoleEnum authorizationRoleEnumDV = AuthorizationRoleEnum.DV_F;
        AccessRightEnum accessRightDV = AccessRightEnum.READ_ACCESS_DG3_AND_DG4;
        CVCertificateBody cdv = new CVCertificateBody(caReferenceFieldDV, org.ejbca.cvc.KeyFactory.createInstance(publicKey, dataCV.getSignatureAlgoritm(), authorizationRoleEnumDV), holderReferenceFieldDV, authorizationRoleEnumDV, accessRightDV, notBeforeDV, notAfter);

        Signature signature = Signature.getInstance(dataCV.getSignatureAlgoritm());
        signature.initSign(dataCV.getPrivateKey());
        signature.update(cdv.getDEREncoded());
        byte[] signDV = signature.sign();

        CardVerifiableCertificate dv = new CardVerifiableCertificate(authorityPrincipalDV, holderReferenceDV, publicKey, dataCV.getSignatureAlgoritm(), notBeforeDV, notAfter, roleDV, permissionDV, signDV);
        println(dv);
        File outFileDV = new File("dv-" + authorityPrincipalDV.getName()+".cvcert");
        FileOutputStream fosDV = new FileOutputStream(outFileDV);
        fosDV.write(dv.getEncoded());
        fosDV.close();

        dataDV = new DataDV(dv, publicKey, privateKey, holderReferenceDV, notBeforeDV, notAfter);
        createIS();
    }

    DataIS dataIS;
    public void createIS() throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException, ConstructionException, CertificateEncodingException {
        println("\n============================================\n");
        KeyPair keyPair = Generate.generaterKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        CVCPrincipal holderReferenceIS = new CVCPrincipal("IDPURAEPPIS001");
        Date notBefore = new Date(System.currentTimeMillis());
        Date notAfter;
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(notBefore);
        calendar.add(Calendar.YEAR, 3);
        calendar.add(Calendar.MONTH, -2);
        notAfter = calendar.getTime();

        CVCPrincipal authorityPrincipalIS = dataDV.getCvcPrincipal();
        CVCAuthorizationTemplate.Role roleIS = CVCAuthorizationTemplate.Role.IS;
        CVCAuthorizationTemplate.Permission permissionIS = CVCAuthorizationTemplate.Permission.READ_ACCESS_DG3_AND_DG4;

        CAReferenceField caReferenceFieldIS = new CAReferenceField(authorityPrincipalIS.getCountry().toAlpha2Code(), authorityPrincipalIS.getMnemonic(), authorityPrincipalIS.getSeqNumber());
        HolderReferenceField holderReferenceFieldIS = new HolderReferenceField(holderReferenceIS.getCountry().toAlpha2Code(), holderReferenceIS.getMnemonic(), holderReferenceIS.getSeqNumber());

        AuthorizationRoleEnum authorizationRoleEnumIS = AuthorizationRoleEnum.IS;
        AccessRightEnum accessRightIS = AccessRightEnum.READ_ACCESS_DG3_AND_DG4;
        CVCertificateBody body = new CVCertificateBody(caReferenceFieldIS, org.ejbca.cvc.KeyFactory.createInstance(publicKey, dataCV.getSignatureAlgoritm(), authorizationRoleEnumIS), holderReferenceFieldIS, authorizationRoleEnumIS, accessRightIS, notBefore, notAfter);

        Signature signature = Signature.getInstance(dataCV.getSignatureAlgoritm());
        signature.initSign(dataDV.getPrivateKey());
        signature.update(body.getDEREncoded());
        byte[] signIS = signature.sign();

        CardVerifiableCertificate is = new CardVerifiableCertificate(authorityPrincipalIS, holderReferenceIS, publicKey, dataCV.getSignatureAlgoritm(), notBefore, notAfter, roleIS, permissionIS, signIS);
        println(is);
        File outFileDV = new File("is-" + authorityPrincipalIS.getName()+".cvcert");
        FileOutputStream fosIS = new FileOutputStream(outFileDV);
        fosIS.write(is.getEncoded());
        fosIS.close();
    }

    public void signOut() {
        try {
            if (session != null) {
                session.logout();
                module.finalize(null);
            }
        } catch (PKCS11Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void println(Object msg) {
        System.out.println(msg);
    }

    public byte[] getSignatureByte() {
        return signatureByte;
    }

    public void setSignatureByte(byte[] signatureByte) {
        this.signatureByte = signatureByte;
    }

    public void setSignatureString(String sign) {
        this.signatureString = sign;
    }

    public String getSignatureString() {
        return signatureString;
    }

    public long getKeyPublic() {
        return keyPublic;
    }

    public void setKeyPublic(long keyPublic) {
        this.keyPublic = keyPublic;
    }

    public long getKeyPrivate() {
        return keyPrivate;
    }

    public void setKeyPrivate(long keyPrivate) {
        this.keyPrivate = keyPrivate;
    }
}
