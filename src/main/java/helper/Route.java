package helper;

import com.formdev.flatlaf.extras.FlatAnimatedLafChange;
import ui.Application;

import javax.swing.*;
import java.awt.*;

public class Route {

    private static Route INSTANCE;
    private Application application;

    public Route() {
    }

    public static Route getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new Route();
        }
        return INSTANCE;
    }

    public void initApplication(Application application) {
        this.application = application;
    }
    public void showForm(JComponent form) {
        EventQueue.invokeLater(() -> {
            FlatAnimatedLafChange.showSnapshot();
            application.setContentPane(form);
            application.revalidate();
            application.repaint();
            FlatAnimatedLafChange.hideSnapshotWithAnimation();
        });
    }
}
