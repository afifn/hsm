package ui;

import com.formdev.flatlaf.FlatClientProperties;
import data.model.KeyMechanism;
import helper.Hsm;
import net.miginfocom.swing.MigLayout;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import raven.toast.Notifications;
import utils.Const;
import utils.KeyConstant;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class Verification extends JPanel {
    private Hsm hsm;
    private List<String> keyList = new ArrayList<>();
    private List<KeyMechanism> keyMechanismList = new ArrayList<>();
    private JComboBox<String> spinnerKey = new JComboBox<>();
    private JComboBox<KeyMechanism> spinnerMechanism = new JComboBox<>();
    private JTextArea textText = new JTextArea();
    private JTextArea textSign = new JTextArea();
    private JTextArea textResult = new JTextArea();
    private JButton btnVerify = new JButton("Verify");

    private String keyFind;
    private long keyCrypt;
    public Verification() {
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
            KeyMechanism selectedItem = (KeyMechanism) spinnerMechanism.getSelectedItem();
            if (selectedItem != null) {
                long mechanism = selectedItem.getMechanism();
                hsm.setMechanismCrypt(mechanism);
            }
        });
        textSign.setRows(5);
        textSign.setLineWrap(true);
        JScrollPane scrollSign = new JScrollPane(textSign, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        textText.setRows(5);
        textText.setLineWrap(true);
        JScrollPane scrollText = new JScrollPane(textText, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        btnVerify.addActionListener(e -> {
            String signature = textSign.getText();
            String data = textText.getText();
            try {
                hsm.verify(data, signature, keyFind);
                Notifications.getInstance().show(Notifications.Type.SUCCESS, Notifications.Location.TOP_RIGHT, "Berhasil verify data");
            } catch (PKCS11Exception | NullPointerException | IllegalArgumentException | StringIndexOutOfBoundsException ex) {
                Notifications.getInstance().show(Notifications.Type.ERROR, Notifications.Location.BOTTOM_CENTER, ex.getMessage());
                throw new RuntimeException(ex);
            }
        });

        container.add(new JLabel("Key Pair"), "gapy 8");
        container.add(spinnerKey);
        container.add(new JLabel("Key Mechanism"), "gapy 8");
        container.add(spinnerMechanism);
        container.add(new JLabel("Signature"), "gapy 8, split 2");
        container.add(new JLabel("Data"), "gapy 8");
        container.add(scrollSign, "split 2");
        container.add(scrollText);
        container.add(btnVerify, "gapy 10");

        add(container);
    }
}
