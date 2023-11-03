package ui;

import com.formdev.flatlaf.FlatClientProperties;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;

public class Home extends JPanel {

    private JButton btnDashboard = new JButton("Dashboard");
    private JButton btnEncrypt = new JButton("Encrypt");
    private JButton btnDecrypt = new JButton("Decrypt");
    private JButton btnSign = new JButton("Signature");
    private JButton btnVerify = new JButton("Verify");
    private JButton btnCertificate = new JButton("Certificate");

    public Home() {
        init();
    }

    private void init() {
        setLayout(new MigLayout("fill, insets 20", "[fill]", "[fill]"));
        JPanel panel = new JPanel(new MigLayout("fill"));

        JPanel panelSidebar = new JPanel(new MigLayout("wrap, fill, insets 20", "fill, 120:200", "[top]"));
        panelSidebar.putClientProperty(FlatClientProperties.STYLE,"arc:20;" +
                "[light]background:darken(@background, 3%);" +
                "[dark]background:lighten(@background, 3%);");

        JLabel title = new JLabel("HSM");
        title.putClientProperty(FlatClientProperties.STYLE,"");
        JPanel sidebar = new JPanel(new MigLayout("wrap, fill", "fill"));
        sidebar.putClientProperty(FlatClientProperties.STYLE,"arc:20;" +
                "[light]background:darken(@background, 3%);" +
                "[dark]background:lighten(@background, 3%);");
        panelSidebar.add(sidebar);
        sidebar.add(title);
        sidebar.add(btnDashboard);
        sidebar.add(btnEncrypt);
        sidebar.add(btnDecrypt);
        sidebar.add(btnSign);
        sidebar.add(btnVerify);
        sidebar.add(btnCertificate);

        JPanel panelContent = new JPanel(new MigLayout("wrap, fill"));
        panelContent.putClientProperty(FlatClientProperties.STYLE,"arc:20;" +
                "[light]background:darken(@background, 3%);" +
                "[dark]background:lighten(@background, 3%);");

        JScrollPane scrollPane = new JScrollPane(panelContent);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setBorder(null);

        JScrollBar scrollBar = scrollPane.getVerticalScrollBar();
        scrollBar.setUnitIncrement(16);

        JPanel panelDashboard = new Dashboard();
        JPanel panelEncrypt = new Encryption();
        JPanel panelDecrypt = new Decryption();
        JPanel panelSignature = new Signature();
        JPanel panelVerify = new Verification();
        JPanel panelCertificate = new Certificate();

        panelContent.add(panelDashboard, "grow");
        btnDashboard.addActionListener(e -> {
            panelDashboard.setVisible(true);
            panelEncrypt.setVisible(false);
            panelDecrypt.setVisible(false);
            panelSignature.setVisible(false);
            panelVerify.setVisible(false);
            panelCertificate.setVisible(false);

            panelContent.remove(panelEncrypt);
            panelContent.remove(panelDecrypt);
            panelContent.remove(panelSignature);
            panelContent.remove(panelVerify);
            panelContent.remove(panelCertificate);
            panelContent.add(panelDashboard, "grow");
        });
        btnEncrypt.addActionListener(e -> {
            panelDashboard.setVisible(false);
            panelEncrypt.setVisible(true);
            panelDecrypt.setVisible(false);
            panelSignature.setVisible(false);
            panelVerify.setVisible(false);
            panelCertificate.setVisible(false);

            panelContent.remove(panelDashboard);
            panelContent.remove(panelDecrypt);
            panelContent.remove(panelSignature);
            panelContent.remove(panelVerify);
            panelContent.remove(panelCertificate);
            panelContent.add(panelEncrypt, "grow");
        });
        btnDecrypt.addActionListener(e -> {
            panelDashboard.setVisible(false);
            panelEncrypt.setVisible(false);
            panelDecrypt.setVisible(true);
            panelSignature.setVisible(false);
            panelVerify.setVisible(false);
            panelCertificate.setVisible(false);

            panelContent.remove(panelDashboard);
            panelContent.remove(panelEncrypt);
            panelContent.remove(panelSignature);
            panelContent.remove(panelVerify);
            panelContent.remove(panelCertificate);
            panelContent.add(panelDecrypt, "grow");
        });
        btnSign.addActionListener(e -> {
            panelDashboard.setVisible(false);
            panelEncrypt.setVisible(false);
            panelDecrypt.setVisible(false);
            panelSignature.setVisible(true);
            panelVerify.setVisible(false);
            panelCertificate.setVisible(false);

            panelContent.remove(panelDashboard);
            panelContent.remove(panelEncrypt);
            panelContent.remove(panelDecrypt);
            panelContent.remove(panelVerify);
            panelContent.remove(panelCertificate);
            panelContent.add(panelSignature, "grow");
        });
        btnVerify.addActionListener(e -> {
            panelDashboard.setVisible(false);
            panelEncrypt.setVisible(false);
            panelDecrypt.setVisible(false);
            panelSignature.setVisible(false);
            panelVerify.setVisible(true);
            panelCertificate.setVisible(false);

            panelContent.remove(panelDashboard);
            panelContent.remove(panelEncrypt);
            panelContent.remove(panelDecrypt);
            panelContent.remove(panelSignature);
            panelContent.remove(panelCertificate);
            panelContent.add(panelVerify, "grow");
        });
        btnCertificate.addActionListener(e -> {
            panelDashboard.setVisible(false);
            panelEncrypt.setVisible(false);
            panelDecrypt.setVisible(false);
            panelSignature.setVisible(false);
            panelVerify.setVisible(false);
            panelCertificate.setVisible(true);

            panelContent.remove(panelDashboard);
            panelContent.remove(panelEncrypt);
            panelContent.remove(panelDecrypt);
            panelContent.remove(panelSignature);
            panelContent.remove(panelVerify);
            panelContent.add(panelCertificate, "grow");
        });

        panel.add(panelSidebar, "dock west");
        panel.add(scrollPane, "grow, gapx 20");
        add(panel);
    }
}
