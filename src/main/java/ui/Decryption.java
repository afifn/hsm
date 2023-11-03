package ui;

import data.model.KeyMechanism;
import data.model.KeyPair;
import helper.Hsm;
import net.miginfocom.swing.MigLayout;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import raven.toast.Notifications;
import utils.Const;
import utils.KeyConstant;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class Decryption extends JPanel {
    private List<KeyPair> keyPairList = new ArrayList<>();
    private List<KeyMechanism> keyMechanismList = new ArrayList<>();
    private List<String> keyPairListString = new ArrayList<>();

    private JComboBox spinnerKeyGen = new JComboBox();
    private JComboBox spinnerCrypt = new JComboBox();
    private JTextArea textCipher = new JTextArea();
    private JTextArea textResult = new JTextArea();
    private JButton btnDecrypt = new JButton("Decrypt");

    private String keyFind;
    private long keyCrypto;
    private Hsm hsm;

    public Decryption() {
        init();
    }

    private void init() {
        hsm = Hsm.getInstance();
        setLayout(new MigLayout("fill, insets 10", "[center]", "[center]"));
        JPanel container = new JPanel(new MigLayout("wrap, fill", "[fill, 360:400]"));

        keyPairList = KeyConstant.keyPairs();
        keyPairList.add(0, new KeyPair("Choose one", 0));
        keyMechanismList = KeyConstant.keyMechanisms();
        keyMechanismList.add(0, new KeyMechanism("Choose one", 0));

        keyPairListString = Const.keyGen();
        keyPairListString.add(0, "Choose one");

        spinnerKeyGen.setModel(new DefaultComboBoxModel<>(keyPairListString.toArray()));
        spinnerCrypt.setModel(new DefaultComboBoxModel<>(keyMechanismList.toArray(new KeyMechanism[0])));

        spinnerKeyGen.addActionListener(e -> {
            Object selectedItem = spinnerKeyGen.getSelectedItem();
            if (selectedItem != null) {
                keyFind = selectedItem.toString();
            }
        });
        spinnerCrypt.addActionListener(e -> {
            KeyMechanism selectedItem = (KeyMechanism) spinnerCrypt.getSelectedItem();
            if (selectedItem != null) {
                keyCrypto = selectedItem.getMechanism();
                hsm.setMechanismCrypt(keyCrypto);
            }
        });
        btnDecrypt.addActionListener(e -> {
            String cipher = textCipher.getText();
            try {
                String decrypt = hsm.decrypt(cipher, keyFind);
                textResult.setText(decrypt);
                Notifications.getInstance().show(Notifications.Type.SUCCESS, Notifications.Location.TOP_RIGHT, "Berhasil decrypt data");
            } catch (PKCS11Exception ex) {
                Notifications.getInstance().show(Notifications.Type.ERROR, Notifications.Location.BOTTOM_CENTER, ex.getMessage());
                throw new RuntimeException(ex);
            } catch (ArrayIndexOutOfBoundsException ex) {
                Notifications.getInstance().show(Notifications.Type.ERROR, Notifications.Location.BOTTOM_CENTER, "Key tidak tersedia");
            }
        });

        JScrollPane scrollPane = new JScrollPane();
        JScrollPane scrollPane1 = new JScrollPane();
        textCipher.setLineWrap(true);
        textCipher.setRows(5);
        scrollPane.setViewportView(textCipher);

        textResult.setLineWrap(true);
        textResult.setRows(5);
        scrollPane1.setViewportView(textResult);

        container.add(new JLabel("Key Pair"), "gapy 8");
        container.add(spinnerKeyGen);
        container.add(new JLabel("Key Mechanism"), "gapy 8");
        container.add(spinnerCrypt);
        container.add(new JLabel("Cipher"), "gapy 8");
        container.add(textCipher);
        container.add(btnDecrypt, "gapy 10");
        container.add(new JLabel("Result"), "gapy 10");
        container.add(textResult);

        add(container);
    }
}
