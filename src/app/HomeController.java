package app;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.ListView;

import java.io.InputStream;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.ResourceBundle;

public class HomeController implements Initializable {

    @FXML
    private ListView<String> examplesList;

    private PrincipalController principalController;

    private Map<String, InputStream> streamMap;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        streamMap = new LinkedHashMap<>();
        streamMap.put("Address Resolution Protocol (ARP)", getClass().getResourceAsStream("arp.txt"));
        examplesList.getItems().add("Address Resolution Protocol (ARP)");
        streamMap.put("Dynamic Host Configuration Protocol (DHCP)", getClass().getResourceAsStream("dhcp.txt"));
        examplesList.getItems().add("Dynamic Host Configuration Protocol (DHCP)");
        streamMap.put("Domain Name System (DNS)", getClass().getResourceAsStream("dns.txt"));
        examplesList.getItems().add("Domain Name System (DNS)");
        streamMap.put("Internet Protocol Version 6 (IPv6)", getClass().getResourceAsStream("ipv6.txt"));
        examplesList.getItems().add("Internet Protocol Version 6 (IPv6)");
        streamMap.put("Internet Control Message Protocol (ICMP)", getClass().getResourceAsStream("icmp.txt"));
        examplesList.getItems().add("Internet Control Message Protocol (ICMP)");
        streamMap.put("Transmission Control Protocol (TCP)", getClass().getResourceAsStream("tcp.txt"));
        examplesList.getItems().add("Transmission Control Protocol (TCP)");
        streamMap.put("User Datagram Protocol (UDP)", getClass().getResourceAsStream("/udp.txt"));
        examplesList.getItems().add("User Datagram Protocol (UDP)");
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
        String example = examplesList.getSelectionModel().getSelectedItem();
        if (streamMap.containsKey(example))
            principalController.readInputStream(streamMap.get(example));
    }
}
