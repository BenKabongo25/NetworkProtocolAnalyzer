package app;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.ListView;

import java.io.File;
import java.net.URL;
import java.util.Objects;
import java.util.ResourceBundle;

public class HomeController implements Initializable {

    @FXML
    private ListView<File> examplesList;

    private PrincipalController principalController;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        examplesList.getItems().add(new File("ressources/frames/arp.txt"));
        examplesList.getItems().add(new File("ressources/frames/dhcp.txt"));
        examplesList.getItems().add(new File("ressources/frames/dns.txt"));
        examplesList.getItems().add(new File("ressources/frames/icmp.txt"));
        examplesList.getItems().add(new File("ressources/frames/ipv6.txt"));
        examplesList.getItems().add(new File("ressources/frames/tcp.txt"));
        examplesList.getItems().add(new File("ressources/frames/udp.txt"));
    }

    public void init(PrincipalController principalController) {
        this.principalController = principalController;
    }

    @FXML
    private void openHandle() {
        principalController.handleOpen();
    }

    @FXML
    private void helpHandle() {
        principalController.handleHelp();
    }

    @FXML
    private void aboutUsHandle() {
        principalController.handleAboutUs();
    }

    @FXML
    private void openExampleHandle() {
        principalController.openFile(examplesList.getSelectionModel().getSelectedItem());
    }
}
