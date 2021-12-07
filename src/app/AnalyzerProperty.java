package app;

import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;
import model.analyzers.AnalyzerException;
import model.analyzers.ethernet.EthernetAnalyzer;

public class AnalyzerProperty {

    private final SimpleIntegerProperty noProperty;
    private final SimpleStringProperty sourceProperty;
    private final SimpleStringProperty destinationProperty;
    private final SimpleStringProperty protocolProperty;
    private final SimpleIntegerProperty lengthProperty;
    private final SimpleStringProperty analyzeInformationProperty;

    private final int no;
    private final EthernetAnalyzer analyzer;
    private final AnalyzerException analyzerException;

    public AnalyzerProperty(int no, EthernetAnalyzer analyzer, AnalyzerException analyzerException) {
        this.no = no;
        this.analyzer = analyzer;
        this.analyzerException = analyzerException;
        noProperty = new SimpleIntegerProperty(no + 1);
        sourceProperty = new SimpleStringProperty("");
        if (analyzer.getMacSource() != null)
            sourceProperty.set(analyzer.getMacSource().toString());
        destinationProperty = new SimpleStringProperty("");
        if (analyzer.getMacDestination() != null)
            destinationProperty.set(analyzer.getMacDestination().toString());
        protocolProperty = new SimpleStringProperty(analyzer.getProtocolName());
        lengthProperty = new SimpleIntegerProperty(analyzer.getT().length);
        analyzeInformationProperty = new SimpleStringProperty("Successful analysis");
        if (analyzerException != null)
            analyzeInformationProperty.set(analyzerException.getMessage());
    }

    public AnalyzerProperty(int no, EthernetAnalyzer analyzer) {
        this(no, analyzer, null);
    }

    public int getNoProperty() {
        return noProperty.get();
    }

    public SimpleIntegerProperty noPropertyProperty() {
        return noProperty;
    }

    public String getSourceProperty() {
        return sourceProperty.get();
    }

    public SimpleStringProperty sourcePropertyProperty() {
        return sourceProperty;
    }

    public String getDestinationProperty() {
        return destinationProperty.get();
    }

    public SimpleStringProperty destinationPropertyProperty() {
        return destinationProperty;
    }

    public String getProtocolProperty() {
        return protocolProperty.get();
    }

    public SimpleStringProperty protocolPropertyProperty() {
        return protocolProperty;
    }

    public int getLengthProperty() {
        return lengthProperty.get();
    }

    public SimpleIntegerProperty lengthPropertyProperty() {
        return lengthProperty;
    }

    public String getAnalyzeInformationProperty() {
        return analyzeInformationProperty.get();
    }

    public SimpleStringProperty analyzeInformationPropertyProperty() {
        return analyzeInformationProperty;
    }

    public int getNo() {
        return no;
    }

    public EthernetAnalyzer getAnalyzer() {
        return analyzer;
    }

    public AnalyzerException getAnalyzerException() {
        return analyzerException;
    }
}
