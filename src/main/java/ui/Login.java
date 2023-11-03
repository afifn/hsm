package ui;

import com.formdev.flatlaf.FlatClientProperties;
import helper.Hsm;
import helper.Route;
import net.miginfocom.swing.MigLayout;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import raven.toast.Notifications;

import javax.swing.*;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;

public class Login extends JPanel {
    private JTextField txtSlot;
    private JPasswordField txtPassword;
    private JCheckBox chRemember;
    private JButton btnLogin;

    Login() {
        init();
    }

    private void init() {
        setLayout(new MigLayout("fill, insets 20", "[center]", "[center]"));

        txtSlot = new JTextField(10);
        ((AbstractDocument) txtSlot.getDocument()).setDocumentFilter(new NumberFilter());

        txtPassword = new JPasswordField();
        chRemember = new JCheckBox("Remember me");
        btnLogin = new JButton("Login");
        JPanel panel = new JPanel(new MigLayout("wrap, fill, insets 35 43 30 45", "fill, 250:280"));
        panel.putClientProperty(FlatClientProperties.STYLE,
                "arc:20;" +
                        "[light]background:darken(@background, 3%);" +
                        "[dark]background:lighten(@background, 3%);");

        txtSlot.putClientProperty(FlatClientProperties.PLACEHOLDER_TEXT, "Enter your slot");
        txtPassword.putClientProperty(FlatClientProperties.PLACEHOLDER_TEXT, "Enter your password");
        txtPassword.putClientProperty(FlatClientProperties.STYLE,
                "showRevealButton:true");
        btnLogin.putClientProperty(FlatClientProperties.STYLE,
                "[light]foreground:lighten(@foreground, 10%);" +
                        "[dark]foreground:darken(@foreground, 10%);" +
                        "borderWidth:0;" +
                        "focusWidth:0;" +
                        "innerFocusWidth:0;");
        btnLogin.addActionListener(e -> {
            char[] passwordChars = txtPassword.getPassword();
            String slot = txtSlot.getText();
            String password = new String(passwordChars);

            if (slot.isEmpty()) {
                Notifications.getInstance().show(Notifications.Type.INFO, Notifications.Location.TOP_RIGHT, "Slot can't be empty");
            } else if (password.isEmpty()) {
                Notifications.getInstance().show(Notifications.Type.INFO, Notifications.Location.TOP_RIGHT, "Password can't be empty");
            } else {
                Hsm hsm = Hsm.getInstance();
//                Route.getInstance().showForm(new Home());
                try {
                    hsm.slot(Integer.parseInt(slot));
                    hsm.auth(PKCS11Constants.CKU_USER, password);
                    Route.getInstance().showForm(new Home());
                } catch (PKCS11Exception | ArrayIndexOutOfBoundsException ex) {
                    Notifications.getInstance().show(Notifications.Type.ERROR, Notifications.Location.BOTTOM_CENTER, "PIN Incorrect");
                    throw new RuntimeException(ex);
                }
            }


        });

        JLabel lbTitle = new JLabel("Welcome back!");
        lbTitle.putClientProperty(FlatClientProperties.STYLE,
                "font:bold +10");
        JLabel description = new JLabel("Please sign in to access your account");
        description.putClientProperty(FlatClientProperties.STYLE,
                "[light]foreground:lighten(@foreground, 30%);" +
                        "[dark]foreground:darken(@foreground, 30%);");

        panel.add(lbTitle);
        panel.add(description);
        panel.add(new JLabel("Slot"), "gapy 8");
        panel.add(txtSlot);
        panel.add(new JLabel("Password"), "gapy 8");
        panel.add(txtPassword);
        panel.add(chRemember, "grow 8");
        panel.add(btnLogin, "gapy 10");
        add(panel);
    }

    static class NumberFilter extends DocumentFilter {
        @Override
        public void insertString(DocumentFilter.FilterBypass fb, int offset, String string, AttributeSet attr) throws BadLocationException {
            if (string.matches("\\d+")) {
                super.insertString(fb, offset, string, attr);
            }
        }

        @Override
        public void replace(DocumentFilter.FilterBypass fb, int offset, int length, String text, AttributeSet attrs) throws BadLocationException {
            if (text.matches("\\d+")) {
                super.replace(fb, offset, length, text, attrs);
            }
        }
    }
}
