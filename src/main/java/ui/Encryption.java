package ui;

import com.formdev.flatlaf.FlatClientProperties;
import data.model.KeyMechanism;
import data.model.KeyPair;
import helper.Hsm;
import net.miginfocom.swing.MigLayout;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import raven.toast.Notifications;
import utils.Const;
import utils.KeyConstant;
import utils.Print;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class Encryption extends JPanel {
    private List<KeyPair> keyPairList = new ArrayList<>();
    private List<KeyMechanism> keyMechanismList = new ArrayList<>();
    private List<String> keyPairListString = new ArrayList<>();
    private JComboBox<String> spinnerKeyPair;
    private JComboBox<KeyMechanism> spinnerKeyMechanism;
    private JTextArea edtPlain = new JTextArea();
    private JTextArea edtResult = new JTextArea();
    private JButton btnEncrypt = new JButton("Encrypt");

    private long keyCrypto;
    private String keyFind;
    private Hsm hsm;
    public Encryption() {
        init();
    }

    private void init() {
        hsm = Hsm.getInstance();
        setLayout(new MigLayout("fill, insets 10", "[center]", "[center]"));
        JPanel container = new JPanel(new MigLayout("wrap, fill", "[fill, 360:400]"));
        container.putClientProperty(FlatClientProperties.STYLE, "arc:20;");

        keyPairList = KeyConstant.keyPairs();
        keyPairList.add(0, new KeyPair("Choose one",0));
        keyMechanismList = KeyConstant.keyMechanisms();
        keyMechanismList.add(0, new KeyMechanism("Choose one",0));

        keyPairListString = Const.keyGen();
        keyPairListString.add(0, "Choose one");

        spinnerKeyPair = new JComboBox<>();
//        spinnerKeyPair.setModel(new DefaultComboBoxModel<>(keyPairList.toArray(new KeyPair[0])));
        spinnerKeyPair.setModel(new DefaultComboBoxModel<>(keyPairListString.toArray(new String[0])));
        spinnerKeyMechanism = new JComboBox<>();
        spinnerKeyMechanism.setModel(new DefaultComboBoxModel<>(keyMechanismList.toArray(new KeyMechanism[0])));
        spinnerKeyPair.addActionListener(e -> {
            Object selectedItem = spinnerKeyPair.getSelectedItem();
            if (selectedItem != null) {
                keyFind = selectedItem.toString();
            }
//            KeyPair keyPair = (KeyPair) spinnerKeyPair.getSelectedItem();
//            if (keyPair != null) {
//                keyGenerate = keyPair.getMechanism();
//                hsm.setMechanismKeyGen(keyGenerate);
//            }
//            Print.printLn(keyGenerate);
        });
        spinnerKeyMechanism.addActionListener(e -> {
            KeyMechanism keyMechanism = (KeyMechanism) spinnerKeyMechanism.getSelectedItem();
            if (keyMechanism != null) {
                keyCrypto = keyMechanism.getMechanism();
                hsm.setMechanismCrypt(keyCrypto);
            }
            Print.printLn(keyCrypto);
        });
        JScrollPane scrollPane = new JScrollPane();
        JScrollPane scrollPane1 = new JScrollPane();
        edtPlain.setRows(5);
        edtPlain.setLineWrap(true);
        scrollPane.setViewportView(edtPlain);

        edtResult.setRows(5);
        edtResult.setLineWrap(true);
        scrollPane1.setViewportView(edtResult);

        btnEncrypt.addActionListener(e -> {
            String plainText = edtPlain.getText();
            try {
                String encrypt = hsm.encrypt(plainText, 16, keyFind);
                edtResult.setText(encrypt);
                Notifications.getInstance().show(Notifications.Type.SUCCESS, Notifications.Location.TOP_RIGHT, "Berhasil encrypt data");
            } catch (PKCS11Exception | NullPointerException ex) {
                Notifications.getInstance().show(Notifications.Type.ERROR, Notifications.Location.BOTTOM_CENTER, ex.getMessage());
                throw new RuntimeException(ex);
            } catch (ArrayIndexOutOfBoundsException ex) {
                Notifications.getInstance().show(Notifications.Type.ERROR, Notifications.Location.BOTTOM_CENTER, "Key tidak tersedia");
            }
        });

        container.add(new JLabel("Key Pair"), "gapy 8");
        container.add(spinnerKeyPair);
        container.add(new JLabel("Key Mechanism"), "gapy 8");
        container.add(spinnerKeyMechanism);
        container.add(new JLabel("Plain Text"), "gapy 8");
        container.add(edtPlain);
        container.add(btnEncrypt, "gapy 10");
        container.add(new JLabel("Result"), "gapy 10");
        container.add(edtResult);
        add(container);
    }
}
