package ui;

import com.formdev.flatlaf.FlatClientProperties;
import com.github.lgooddatepicker.components.DatePicker;
import data.model.CertificateData;
import data.model.FormCert;
import helper.Hsm;
import net.miginfocom.swing.MigLayout;
import org.bouncycastle.operator.OperatorCreationException;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import raven.toast.Notifications;
import utils.Const;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

public class Certificate extends JPanel {
    private Hsm hsm;
    private List<String> keyPubList = new ArrayList<>();
    private List<String> keyPrivList = new ArrayList<>();
    private JTextField textCN = new JTextField();
    private JTextField textOrgz = new JTextField();
    private JTextField textCountry = new JTextField();
    private DatePicker textStartDate = new DatePicker();
    private DatePicker textEndDate = new DatePicker();
    private JTextField textLocation = new JTextField();
    private JTextField textState = new JTextField();
    private JTextField textIssuer = new JTextField();
    private JButton btnCreate = new JButton("Create");
    private JComboBox<String> spinnerPub = new JComboBox<>();
    private JComboBox<String> spinnerPriv = new JComboBox<>();
    private String findPub;
    private String findPriv;
    private JTabbedPane tabbedPane;

    public Certificate() {
        init();
    }

    private void init() {
        hsm = Hsm.getInstance();
        setLayout(new MigLayout("fill, insets 10", "[center]", "[center]"));

        tabbedPane = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);
        tabbedPane.addTab("Generate", createGenerateCertificate());
        tabbedPane.addTab("Verify", createVerifyCertificate());

        add(tabbedPane);
    }

    private Component createGenerateCertificate() {
        JPanel container = new JPanel(new MigLayout("wrap, fill", "[fill, 360:400]"));

        keyPubList = Const.keyCertificate();
        keyPrivList = Const.keyCertificate();
        keyPubList.add(0, "Choose one");
        keyPrivList.add(0, "Choose one");
        spinnerPub.setModel(new DefaultComboBoxModel<>(keyPubList.toArray(new String[0])));
        spinnerPriv.setModel(new DefaultComboBoxModel<>(keyPrivList.toArray(new String[0])));
        spinnerPub.addActionListener(e -> {
            Object selectedItem = spinnerPub.getSelectedItem();
            if (selectedItem != null) {
                findPub = selectedItem.toString();
            }
        });
        spinnerPriv.addActionListener(e -> {
            Object selectedItem = spinnerPriv.getSelectedItem();
            if (selectedItem != null) {
                findPriv = selectedItem.toString();
            }
        });

        textStartDate.setLocale(new Locale("id","ID"));
        textStartDate.setDateToToday();

        LocalDate currentDate = LocalDate.now();
        LocalDate nextYear = currentDate.plusYears(1);
        textEndDate.setLocale(new Locale("id", "ID"));
        textEndDate.setDate(nextYear);

        textCN.setText("Pura");
        textOrgz.setText("PST");
        textCountry.setText("Indonesia");
        textLocation.setText("Kudus");
        textState.setText("Central Java");
        textIssuer.setText("Pura Certificate Authority");

        btnCreate.addActionListener(e -> {
            String cn = textCN.getText();
            String organization = textOrgz.getText();
            String country = textCountry.getText();
            String location = textLocation.getText();
            String state = textState.getText();
            String issuer = textIssuer.getText();
            String startDate = textStartDate.getText();
            String endDate = textEndDate.getText();

            try {
                FormCert cert = new FormCert(issuer, cn, organization, country, state, location, startDate, endDate);
                hsm.certificate(findPub, findPriv, cert);
                Notifications.getInstance().show(Notifications.Type.SUCCESS, Notifications.Location.TOP_RIGHT, "Berhasil membuat certificate");
            } catch (PKCS11Exception | IOException | CertificateException | OperatorCreationException | NullPointerException ex) {
                Notifications.getInstance().show(Notifications.Type.ERROR, Notifications.Location.BOTTOM_CENTER, ex.getMessage());
                throw new RuntimeException(ex);
            } catch (ParseException ex) {
                throw new RuntimeException(ex);
            }
        });
        container.add(new JLabel("Certificate Data"), "gapy 8");
        container.add(new JLabel("Public Key"), "split 2, gapy 10");
        container.add(new JLabel("Private Key"));
        container.add(spinnerPub, "split 2");
        container.add(spinnerPriv);
        container.add(new JLabel("Company Name"), "gapy 8");
        container.add(textCN);
        container.add(new JLabel("Organization"), "gapy 8");
        container.add(textOrgz);
        container.add(new JLabel("Country"), "gapy 8");
        container.add(textCountry);
        container.add(new JLabel("Location"), "gapy 8");
        container.add(textLocation);
        container.add(new JLabel("State"), "gapy 8");
        container.add(textState);
        container.add(new JLabel("Issuer"), "gapy 8");
        container.add(textIssuer);
        container.add(new JLabel("Valid Date"), "gapy 8");
        container.add(textStartDate);
        container.add(new JLabel("Until Date"), "gapy 8");
        container.add(textEndDate);
        container.add(btnCreate, "gapy 10");
        return container;
    }
    private Component createVerifyCertificate() {
        JTextField textIssuer = new JTextField();
        JTextField textIssuer2 = new JTextField();
        JTextField validFrom = new JTextField();
        JTextField validFrom2 = new JTextField();
        JTextField validUntil = new JTextField();
        JTextField validUntil2 = new JTextField();
        JTextField signature = new JTextField();
        JTextField signature2 = new JTextField();

        textIssuer.setEnabled(false);
        textIssuer2.setEnabled(false);
        validFrom.setEnabled(false);
        validFrom2.setEnabled(false);
        validUntil.setEnabled(false);
        validUntil2.setEnabled(false);
        signature.setEnabled(false);
        signature2.setEnabled(false);

        JButton uploadButton = new JButton("Upload File");
        JButton uploadButton2 = new JButton("Upload File");

        JTextField textFile = new JTextField();
        JTextField textFile2 = new JTextField();

        JPanel container = new JPanel(new MigLayout("wrap, fill", "[fill]"));
        JPanel left = new JPanel(new MigLayout("wrap, fill", "[fill]", "[top]"));
        left.putClientProperty(FlatClientProperties.STYLE, "arc:20;"+
                "[light]background:darken(@background, 3%);" +
                        "[dark]background:lighten(@background, 3%);");
        JPanel right = new JPanel(new MigLayout("wrap, fill", "[fill]", "[top]"));
        right.putClientProperty(FlatClientProperties.STYLE,  "arc:20;" +
                "[light]background:darken(@background, 3%);" +
                        "[dark]background:lighten(@background, 3%);");

        uploadButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            int returnValue = fileChooser.showOpenDialog(null);

            if (returnValue == JFileChooser.APPROVE_OPTION) {
                java.io.File selectedFile = fileChooser.getSelectedFile();

                String absolutePath = selectedFile.getAbsolutePath();
                textFile.setText(absolutePath);
                try {
                    CertificateData cert = hsm.getExtractCertificate(selectedFile);
                    textIssuer.setText(cert.getCn());
                    validFrom.setText(cert.getStDate());
                    validUntil.setText(cert.getEnDate());
                    signature.setText(cert.getAlgorithm());
                } catch (CertificateException | FileNotFoundException ex) {
                    throw new RuntimeException(ex);
                }
            }
        });
        uploadButton2.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            int returnValue = fileChooser.showOpenDialog(null);

            if (returnValue == JFileChooser.APPROVE_OPTION) {
                java.io.File selectedFile = fileChooser.getSelectedFile();
                String absolutePath = selectedFile.getAbsolutePath();
                textFile2.setText(absolutePath);
                try {
                    CertificateData cert = hsm.getExtractCertificate(selectedFile);
                    textIssuer2.setText(cert.getCn());
                    validFrom2.setText(cert.getStDate());
                    validUntil2.setText(cert.getEnDate());
                    signature2.setText(cert.getAlgorithm());
                } catch (CertificateException | FileNotFoundException ex) {
                    throw new RuntimeException(ex);
                }
            }
        });
        JButton btnVerify = new JButton("Verify");
        btnVerify.addActionListener(e -> {
            File file = new File(textFile.getText());
            File file1 = new File(textFile2.getText());

            try {
                hsm.verifyCertificates(file, file1);
                Notifications.getInstance().show(Notifications.Type.SUCCESS, Notifications.Location.TOP_RIGHT, "Berhasil verify certificate");
            } catch (CertificateException | NoSuchAlgorithmException | SignatureException |
                     InvalidKeyException | NoSuchProviderException ex) {
                Notifications.getInstance().show(Notifications.Type.ERROR, Notifications.Location.BOTTOM_CENTER, ex.getMessage());
                throw new RuntimeException(ex);
            } catch (FileNotFoundException exception) {
                Notifications.getInstance().show(Notifications.Type.ERROR, Notifications.Location.BOTTOM_CENTER, "File not found");
            }
        });
        left.add(new JLabel("CA"));
        left.add(uploadButton);
        left.add(textFile);
        left.add(new JLabel("Issuer"), "gapy 10");
        left.add(textIssuer);
        left.add(new JLabel("Valid From"), "gapy 8");
        left.add(validFrom);
        left.add(new JLabel("Valid Until"), "gapy 8");
        left.add(validUntil);
        left.add(new JLabel("Signature"), "gapy 8");
        left.add(signature);


        right.add(new JLabel("DSC"));
        right.add(uploadButton2);
        right.add(textFile2);
        right.add(new JLabel("Issuer"), "gapy 10");
        right.add(textIssuer2);
        right.add(new JLabel("Valid From"), "gapy 8");
        right.add(validFrom2);
        right.add(new JLabel("Valid Until"), "gapy 8");
        right.add(validUntil2);
        right.add(new JLabel("Signature"), "gapy 8");
        right.add(signature2);

        container.add(left, "grow");
        container.add(right, "grow");
        container.add(btnVerify);
        return container;
    }
}
