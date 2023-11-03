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

public class Signature extends JPanel {
    private Hsm hsm;
    private List<String> keyList = new ArrayList<>();
    private List<KeyMechanism> keyMechanismList = new ArrayList<>();
    private JComboBox<String> spinnerKey = new JComboBox<>();
    private JComboBox<KeyMechanism> spinnerMechanism = new JComboBox<>();
    private JTextArea textSign = new JTextArea();
    private JTextArea textResult = new JTextArea();
    private JButton btnSignature = new JButton("Signature");

    private String keyFind;
    private long keyCrypt;
    public Signature() {
        init();
    }

    private void init() {
        hsm = Hsm.getInstance();
        setLayout(new MigLayout("fill", "[center]", "[center]"));
        JPanel container = new JPanel(new MigLayout("wrap, fill", "[fill, 360:400]"));
        container.putClientProperty(FlatClientProperties.STYLE, "arc:20;");

        keyList = Const.keySignVerify();
        keyList.add(0, "Choose one");
        keyMechanismList = KeyConstant.keyMechanismsSignature();
        keyMechanismList.add(0, new KeyMechanism("Choose one", 0));

        spinnerKey.setModel(new DefaultComboBoxModel<>(keyList.toArray(new String[0])));
        spinnerMechanism.setModel(new DefaultComboBoxModel<>(keyMechanismList.toArray(new KeyMechanism[0])));

        spinnerKey.addActionListener(e -> {
            Object selectedItem = spinnerKey.getSelectedItem();
            if (selectedItem != null) {
                keyFind = selectedItem.toString();
            }
        });
        spinnerMechanism.addActionListener(e -> {
            KeyMechanism mechanism = (KeyMechanism) spinnerMechanism.getSelectedItem();
            if (mechanism != null) {
                keyCrypt = mechanism.getMechanism();
                hsm.setMechanismCrypt(keyCrypt);
                Print.printLn(keyCrypt);
            }
        });
        textSign.setLineWrap(true);
        textSign.setRows(5);

        textResult.setLineWrap(true);
        textResult.setRows(5);

        btnSignature.addActionListener(e -> {
            String data = textSign.getText();
            try {
                String signature = hsm.signature(data, keyFind);
                textResult.setText(signature);
                Notifications.getInstance().show(Notifications.Type.SUCCESS, Notifications.Location.TOP_RIGHT, "Signature berhasil");
            } catch (PKCS11Exception | NullPointerException | IllegalArgumentException ex) {
                Notifications.getInstance().show(Notifications.Type.ERROR, Notifications.Location.BOTTOM_CENTER, ex.getMessage());
                throw new RuntimeException(ex);
            }
        });


        container.add(new JLabel("Key Pair"), "gapy 8");
        container.add(spinnerKey);
        container.add(new JLabel("Key Mechanism"), "gapy 8");
        container.add(spinnerMechanism);
        container.add(new JLabel("Signature"), "gapy 8");
        container.add(textSign);
        container.add(btnSignature, "gapy 10");
        container.add(new JLabel("Result"), "gapy 10");
        container.add(textResult);
        add(container);
    }
}
