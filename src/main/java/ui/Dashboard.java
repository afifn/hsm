package ui;

import com.formdev.flatlaf.FlatClientProperties;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;

public class Dashboard extends JPanel {
    public Dashboard() {
        init();
    }

    private void init() {
        setLayout(new MigLayout("fill, insets 20", "[center]", "[center]"));
        JPanel container = new JPanel(new MigLayout("fill"));
        container.add(new JLabel("Dashboard"));

        add(container);
    }
}
