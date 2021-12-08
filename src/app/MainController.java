package app;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.Region;
import model.address.AddressIPv4;
import model.analyzers.AnalyzerException;
import model.analyzers.SimpleAnalyzer;
import model.analyzers.TracesAnalyzer;
import model.analyzers.arp.ARPAnalyzer;
import model.analyzers.dhcp.*;
import model.analyzers.dns.Class;
import model.analyzers.dns.*;
import model.analyzers.ethernet.EthernetAnalyzer;
import model.analyzers.icmp.ICMPAnalyzer;
import model.analyzers.ip.IPOption;
import model.analyzers.ip.IPv4Analyzer;
import model.analyzers.ip.IPv6Analyzer;
import model.analyzers.tcp.TCPAnalyzer;
import model.analyzers.tcp.TCPOption;
import model.analyzers.udp.UDPAnalyzer;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;

public class MainController implements Initializable {

    @FXML
    private TextField filterTextField;

    @FXML
    private TableView<AnalyzerProperty> tracesTableView;

    @FXML
    private TableColumn<AnalyzerProperty, Integer> noColumn;

    @FXML
    private TableColumn<AnalyzerProperty, String> sourceColumn;

    @FXML
    private TableColumn<AnalyzerProperty, String> destinationColumn;

    @FXML
    private TableColumn<AnalyzerProperty, String> protocolColumn;

    @FXML
    private TableColumn<AnalyzerProperty, Integer> lengthColumn;

    @FXML
    private TableColumn<AnalyzerProperty, String> informationsColumn;

    @FXML
    private TextArea traceTextArea;

    @FXML
    private TreeView<String> analyzerView;

    @FXML
    private Label statusLabel;

    private TracesAnalyzer tracesAnalyzer;

    private List<Integer> filtersAnalyzers;

    public void setTracesAnalyzer(TracesAnalyzer tracesAnalyzer) {
        filtersAnalyzers = new ArrayList<>();
        traceTextArea.setText("");
        analyzerView.setRoot(null);
        this.tracesAnalyzer = tracesAnalyzer;
        try {
            tracesAnalyzer.analyze();
        } catch (Exception ignored) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Analysis error");
            alert.setHeaderText("File parsing error");
            alert.setContentText("The file could not be parsed correctly. Please open another one.");
            alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
            alert.showAndWait();
        }
        for (int i = 0; i < tracesAnalyzer.getAnalyzers().size(); i++)
            filtersAnalyzers.add(i);
        displayAnalyzers();
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        filtersAnalyzers = new ArrayList<>();
        noColumn.setCellValueFactory(new PropertyValueFactory<>("noProperty"));
        sourceColumn.setCellValueFactory(new PropertyValueFactory<>("sourceProperty"));
        destinationColumn.setCellValueFactory(new PropertyValueFactory<>("destinationProperty"));
        protocolColumn.setCellValueFactory(new PropertyValueFactory<>("protocolProperty"));
        lengthColumn.setCellValueFactory(new PropertyValueFactory<>("lengthProperty"));
        informationsColumn.setCellValueFactory(new PropertyValueFactory<>("analyzeInformationProperty"));
    }

    @FXML
    private void tableViewClickEvent() {
        AnalyzerProperty analyzerProperty = tracesTableView.getSelectionModel().getSelectedItem();
        if (analyzerProperty == null) return;
        EthernetAnalyzer analyzer = analyzerProperty.getAnalyzer();
        AnalyzerException analyzerException = analyzerProperty.getAnalyzerException();
        displayTrace(analyzer.getT());
        TreeItem<String> root = new TreeItem<>();
        displayAnalyzer(analyzer, root);
        if (analyzerException != null) {
            TreeItem<String> error = new TreeItem<>("Analysis error");
            error.getChildren().add(new TreeItem<>(analyzerException.getMessage()));
            error.getChildren().add(new TreeItem<>("See byte number : " + analyzerException.getByteNumber()));
            root.getChildren().add(error);
        }
        analyzerView.setRoot(root);
        analyzerView.setShowRoot(false);
    }

    @FXML
    private void filterEvent() {
        String filter = filterTextField.getText();

    }


    private void displayTrace(String[] t) {
        String trace = "";
        String zeros = "000000";
        int i = 0;
        while (i < t.length) {
            String offset = Integer.toHexString(i);
            if (offset.length() < 6)
                offset = zeros.substring(0, 6-offset.length()) + offset;
            trace += offset + "\t" + String.join(" ", Arrays.copyOfRange(t, i, Math.min(i + 16, t.length))) + "\n";
            i = Math.min(i + 16, t.length);
        }
        traceTextArea.setText(trace);
    }

    private void displayAnalyzers() {
        tracesTableView.getItems().removeAll();
        ObservableList<AnalyzerProperty> data = FXCollections.observableArrayList();
        for (int no: filtersAnalyzers) {
            EthernetAnalyzer analyzer = tracesAnalyzer.getAnalyzers().get(no);
            AnalyzerException analyzerException = null;
            if (tracesAnalyzer.getAnalyzersExceptions().containsKey(no))
                analyzerException = tracesAnalyzer.getAnalyzersExceptions().get(no);
            data.add(new AnalyzerProperty(no, analyzer, analyzerException));
        }
        tracesTableView.setItems(data);
    }

    private void displayAnalyzer(SimpleAnalyzer analyzer, TreeItem<String> root) {
        root.setValue(analyzer.getRecap());
        for (String key: analyzer.getInformations().keySet()) {
            String[] value = analyzer.getInformations().get(key);
            root.getChildren().add(new TreeItem<>(key + " : " + value[0] + ((value[1].isEmpty()) ? "": " (" + value[1] + ")")));
        }
    }

    private void displayAnalyzer(EthernetAnalyzer analyzer, TreeItem<String> root) {
        TreeItem<String> item = new TreeItem<>();
        displayAnalyzer((SimpleAnalyzer) analyzer, item);
        root.getChildren().add(item);

        if (analyzer.getArpAnalyzer() != null)
            displayAnalyzer(analyzer.getArpAnalyzer(), root);
        else if (analyzer.getIPv4Analyzer() != null)
            displayAnalyzer(analyzer.getIPv4Analyzer(), root);
        else if (analyzer.getIPv6Analyzer() != null)
            displayAnalyzer(analyzer.getIPv6Analyzer(), root);
    }

    private void displayAnalyzer(ARPAnalyzer analyzer, TreeItem<String> root) {
        TreeItem<String> item = new TreeItem<>();
        displayAnalyzer((SimpleAnalyzer) analyzer, item);
        root.getChildren().add(item);
    }

    private void displayAnalyzer(IPv4Analyzer analyzer, TreeItem<String> root) {
        TreeItem<String> item = new TreeItem<>();
        displayAnalyzer((SimpleAnalyzer) analyzer, item);
        root.getChildren().add(item);

        if (analyzer.getTosInformation() != null && !analyzer.getTosInformation().isEmpty()) {
            TreeItem<String> services = new TreeItem<>("Services Field");
            for (String key: analyzer.getTosInformation().keySet()) {
                String[] value = analyzer.getTosInformation().get(key);
                services.getChildren().add(new TreeItem<>(key + " : " + value[0] + ((value[1].isEmpty()) ? "": " (" + value[1] + ")")));
            }
            item.getChildren().add(services);
        }

        if (analyzer.getOptions() != null && !analyzer.getOptions().isEmpty()) {
            TreeItem<String> options = new TreeItem<>("Options");
            for (IPOption option: analyzer.getOptions()) {
                TreeItem<String> optionItem = new TreeItem<>(option.getOptionType().toString());
                optionItem.getChildren().add(new TreeItem<>("Name : " + option.getOptionType().getName()));
                optionItem.getChildren().add(new TreeItem<>("Value : " + option.getOptionType().getValue()));
                optionItem.getChildren().add(new TreeItem<>("Length : " + option.getSize()));
                if (!option.getiPv4Adress().isEmpty()) {
                    for (AddressIPv4 ip: option.getiPv4Adress())
                        optionItem.getChildren().add(new TreeItem<>(option.getOptionType().getName() + " : " + ip));
                }
                options.getChildren().add(optionItem);
            }
            item.getChildren().add(options);
        }

        if (analyzer.getTcpAnalyzer() != null)
            displayAnalyzer(analyzer.getTcpAnalyzer(), root);
        else if (analyzer.getUdpAnalyzer() != null)
            displayAnalyzer(analyzer.getUdpAnalyzer(), root);
        else if (analyzer.getIcmpAnalyzer() != null)
            displayAnalyzer(analyzer.getIcmpAnalyzer(), root);
    }

    private void displayAnalyzer(IPv6Analyzer analyzer, TreeItem<String> root) {
        TreeItem<String> item = new TreeItem<>();
        displayAnalyzer((SimpleAnalyzer) analyzer, item);
        root.getChildren().add(item);

        if (analyzer.getTcpAnalyzer() != null)
            displayAnalyzer(analyzer.getTcpAnalyzer(), root);
        else if (analyzer.getUdpAnalyzer() != null)
            displayAnalyzer(analyzer.getUdpAnalyzer(), root);
        else if (analyzer.getIcmpAnalyzer() != null)
            displayAnalyzer(analyzer.getIcmpAnalyzer(), root);
    }

    private void displayAnalyzer(ICMPAnalyzer analyzer, TreeItem<String> root) {
        TreeItem<String> item = new TreeItem<>();
        displayAnalyzer((SimpleAnalyzer) analyzer, item);
        root.getChildren().add(item);
    }

    private void displayAnalyzer(TCPAnalyzer analyzer, TreeItem<String> root) {
        TreeItem<String> item = new TreeItem<>();
        displayAnalyzer((SimpleAnalyzer) analyzer, item);
        root.getChildren().add(item);

        if (analyzer.getOptions() != null && !analyzer.getOptions().isEmpty()) {
            TreeItem<String> options = new TreeItem<>("Options");
            for (TCPOption option: analyzer.getOptions()) {
                TreeItem<String> optionItem = new TreeItem<>(option.toString());
                optionItem.getChildren().add(new TreeItem<>("Meaning : " + option.getOptionType().getMeaning()));
                optionItem.getChildren().add(new TreeItem<>("Kind : " + option.getKind()));
                optionItem.getChildren().add(new TreeItem<>("Length : " + option.getLength()));
                if (option.getLength() > 0)
                    optionItem.getChildren().add(new TreeItem<>(option.getOptionType().getMeaning() + " : " + option.getValue()));
                options.getChildren().add(optionItem);
            }
            item.getChildren().add(options);
        }

        if (analyzer.getDhcpAnalyzer() != null)
            displayAnalyzer(analyzer.getDhcpAnalyzer(), root);
        else if (analyzer.getDnsAnalyzer() != null)
            displayAnalyzer(analyzer.getDnsAnalyzer(), root);
        else {
            if (analyzer.getData() != null && !analyzer.getData().isEmpty()) {
                TreeItem<String> data = new TreeItem<>("Data, " + (analyzer.getData().length()/2) + " bytes");
                data.getChildren().add(new TreeItem<>(analyzer.getData()));
                root.getChildren().add(data);
            }
        }
    }

    private void displayAnalyzer(UDPAnalyzer analyzer, TreeItem<String> root) {
        TreeItem<String> item = new TreeItem<>();
        displayAnalyzer((SimpleAnalyzer) analyzer, item);
        root.getChildren().add(item);

        if (analyzer.getDhcpAnalyzer() != null)
            displayAnalyzer(analyzer.getDhcpAnalyzer(), root);
        else if (analyzer.getDnsAnalyzer() != null)
            displayAnalyzer(analyzer.getDnsAnalyzer(), root);
        else {
            if (analyzer.getData() != null && !analyzer.getData().isEmpty()) {
                TreeItem<String> data = new TreeItem<>("Data, " + (analyzer.getData().length()/2) + " bytes");
                data.getChildren().add(new TreeItem<>(analyzer.getData()));
                root.getChildren().add(data);
            }
        }
    }

    private void displayAnalyzer(DHCPAnalyzer analyzer, TreeItem<String> root) {
        TreeItem<String> item = new TreeItem<>();
        displayAnalyzer((SimpleAnalyzer) analyzer, item);
        root.getChildren().add(item);

        if (analyzer.getOptionsCount() > 0) {
            TreeItem<String> options = new TreeItem<>("Options");
            for (int i = 0; i < analyzer.getOptionsCount(); i++) {
                TreeItem<String> optionItem = new TreeItem<>();
                if (analyzer.getNumberOptions() != null && analyzer.getNumberOptions().containsKey(i)) {
                    DHCPOption<Long> option = analyzer.getNumberOptions().get(i);
                    optionItem.setValue(option.getOptionType().getName());
                    optionItem.getChildren().add(new TreeItem<>("Name : " + option.getOptionType().getName()));
                    optionItem.getChildren().add(new TreeItem<>("Code : " + option.getOptionType().getCode()));
                    optionItem.getChildren().add(new TreeItem<>("Length : " + option.getLength()));
                    int code = option.getOptionType().getCode();
                    if (code != 0 && code != 255 && code != 80) {
                        if (option.getOptionType().getValueType() == OptionType.ENUM_VALUE) {
                            long value = option.getValue();
                            if (option.getOptionType().equals(OptionType.DHCPMessageTypeOption))
                                optionItem.getChildren().add(new TreeItem<>("Value : " + DHCPMessageType.getDHCPMessageType((int)value).getName()));
                            else if (option.getOptionType().equals(OptionType.OverloadOption))
                                optionItem.getChildren().add(new TreeItem<>("Value : " + Overload.getOptionOverload((int)value).getMeaning()));
                            else if (option.getOptionType().equals(OptionType.NetBIOSOverTCPIPNodeTypeOption)) {
                                optionItem.getChildren().add(new TreeItem<>("Value : " + NetBIOS.getNetBIOS((int)value).getName()));
                            }
                        }
                        optionItem.getChildren().add(new TreeItem<>("Value : " + option.getValue()));
                    }
                }
                else if (analyzer.getStringOptions() != null && analyzer.getStringOptions().containsKey(i)) {
                    DHCPOption<String> option = analyzer.getStringOptions().get(i);
                    optionItem.setValue(option.getOptionType().getName());
                    optionItem.getChildren().add(new TreeItem<>("Name : " + option.getOptionType().getName()));
                    optionItem.getChildren().add(new TreeItem<>("Code : " + option.getOptionType().getCode()));
                    optionItem.getChildren().add(new TreeItem<>("Length : " + option.getLength()));
                    optionItem.getChildren().add(new TreeItem<>("Value : " + option.getValue()));
                }
                else if (analyzer.getIpOptions() != null && analyzer.getIpOptions().containsKey(i)) {
                    DHCPOption<List<AddressIPv4>> option = analyzer.getIpOptions().get(i);
                    optionItem.setValue(option.getOptionType().getName());
                    optionItem.getChildren().add(new TreeItem<>("Name : " + option.getOptionType().getName()));
                    optionItem.getChildren().add(new TreeItem<>("Code : " + option.getOptionType().getCode()));
                    optionItem.getChildren().add(new TreeItem<>("Length : " + option.getLength()));
                    for (AddressIPv4 ip: option.getValue())
                        optionItem.getChildren().add(new TreeItem<>(option.getOptionType().getName() + " : " + ip));
                }
                else if (analyzer.getListNumberOptions() != null && analyzer.getListNumberOptions().containsKey(i)) {
                    DHCPOption<List<Integer>> option = analyzer.getListNumberOptions().get(i);
                    optionItem.setValue(option.getOptionType().getName());
                    optionItem.getChildren().add(new TreeItem<>("Name : " + option.getOptionType().getName()));
                    optionItem.getChildren().add(new TreeItem<>("Code : " + option.getOptionType().getCode()));
                    optionItem.getChildren().add(new TreeItem<>("Length : " + option.getLength()));
                    if (option.getOptionType().equals(OptionType.ParameterRequestListOption)) {
                        for (int value: option.getValue()) {
                            OptionType optionValue = OptionType.getOptionType(value);
                            optionItem.getChildren()
                                    .add(new TreeItem<>(option.getOptionType().getName() + " : (" + value +") " + ((optionValue == null) ? "Unrecognized": optionValue.getName())));
                        }
                    }
                    else {
                        for (int value: option.getValue())
                            optionItem.getChildren().add(new TreeItem<>(option.getOptionType().getName() + " : " + value));
                    }
                }
                options.getChildren().add(optionItem);
            }
            item.getChildren().add(options);
        }

        if (analyzer.getPadding() != null && !analyzer.getPadding().isEmpty()) {
            TreeItem<String> padding = new TreeItem<>("Padding, " + (analyzer.getPadding().length()/2) + " bytes");
            padding.getChildren().add(new TreeItem<>(analyzer.getPadding()));
            root.getChildren().add(padding);
        }
    }

    private void displayAnalyzer(DNSAnalyzer analyzer, TreeItem<String> root) {
        TreeItem<String> item = new TreeItem<>();
        displayAnalyzer((SimpleAnalyzer) analyzer, item);
        root.getChildren().add(item);

        if (analyzer.getQuestions() != null) {
            TreeItem<String> records = new TreeItem<>("Queries");
            for (QuestionRecordFormat record: analyzer.getQuestions()) {
                TreeItem<String> recordItem = new TreeItem<>(record.toString());
                recordItem.getChildren().add(new TreeItem<>("Name : " + record.getName()));
                recordItem.getChildren().add(new TreeItem<>("[Name Length] : " + record.getName().length()));
                recordItem.getChildren().add(new TreeItem<>("[Label Count] : " + record.getName().split("\\.").length));
                recordItem.getChildren().add(new TreeItem<>("Type : " + record.getType() +
                        ((record.getType() == Type.UNRECOGNIZED_TYPE) ? " (" + record.getTypeCode() + ")" :  "")));
                recordItem.getChildren().add(new TreeItem<>("Class : " + record.getClass_() +
                        ((record.getClass_() == Class.UNRECOGNIZED_CLASS) ? " (" + record.getClassCode() + ")" :  "")));
                records.getChildren().add(recordItem);
            }
            item.getChildren().add(records);
        }

        String[] items = new String[]{"Answers", "Authority", "Additional"};
        int[] nb = new int[]{analyzer.getNbAnswer(), analyzer.getNbAuthority(), analyzer.getNbAdditional()};
        List<List<AnswerRecordFormat>> list = Arrays.asList(analyzer.getAnswers(), analyzer.getAuthorities(), analyzer.getAdditionals());

        for (int i = 0; i < 3; i++) {
            if (nb[i] > 0) {
                if (list.get(i) != null) {
                    TreeItem<String> records = new TreeItem<>(items[i]);
                    for (AnswerRecordFormat record : list.get(i)) {
                        TreeItem<String> recordItem = new TreeItem<>(record.toString());
                        recordItem.getChildren().add(new TreeItem<>("Name : " + record.getName()));
                        recordItem.getChildren().add(new TreeItem<>("[Name Length] : " + record.getName().length()));
                        recordItem.getChildren().add(new TreeItem<>("[Label Count] : " + record.getName().split("\\.").length));
                        recordItem.getChildren().add(new TreeItem<>("Type : " + record.getType() +
                                ((record.getType() == Type.UNRECOGNIZED_TYPE) ? " (" + record.getTypeCode() + ")" : "")));
                        recordItem.getChildren().add(new TreeItem<>("Class : " + record.getClass_() +
                                ((record.getClass_() == Class.UNRECOGNIZED_CLASS) ? " (" + record.getClassCode() + ")" : "")));
                        recordItem.getChildren().add(new TreeItem<>("Time to Live : " + record.getTTL()));
                        recordItem.getChildren().add(new TreeItem<>("Data length : " + record.getDataLength()));
                        if (record.getDataLength() > 0) {
                            TreeItem<String> data = new TreeItem<>("Data");
                            data.getChildren().add(new TreeItem<>("Data : " + record.getData()));
                            recordItem.getChildren().add(data);
                        }
                        records.getChildren().add(recordItem);
                    }
                    item.getChildren().add(records);
                }
            }
        }
    }

    public String getAnalyze() {
        AnalyzerProperty analyzerProperty = tracesTableView.getSelectionModel().getSelectedItem();
        if (analyzerProperty == null) return null;
        EthernetAnalyzer analyzer = analyzerProperty.getAnalyzer();
        AnalyzerException analyzerException = analyzerProperty.getAnalyzerException();
        if (analyzerException != null) return null;
        return analyzer.toString();
    }
}
