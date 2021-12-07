package model.analyzers;

import java.util.LinkedHashMap;
import java.util.Map;

public abstract class SimpleAnalyzer extends Analyzer {

    protected static final String HEXADECIMAL_DIGITS = "0123456789ABCDEF";

    /**
     * name of Analyzer
     */
    protected String name;

    protected String nameCode;

    /**
     * fields of Analyzer
     */
    protected final String[] t;

    /**
     * lowest layer protocol name
     */
    protected String protocolName = "";

    /**
     * key = Name of field
     * value = [value, comments]
     */
    protected Map<String, String[]> informations;

    public SimpleAnalyzer(String name, String nameCode, String[] t) {
        this.name = name;
        this.nameCode = nameCode;
        this.t = t;
        this.protocolName = nameCode;
        informations = new LinkedHashMap<>();
    }

    public SimpleAnalyzer(String name, String nameCode, String trace) {
        this(name, nameCode, trace.split(" "));
    }

    public static void checkTrace(String[] t) throws AnalyzerException {
        for (int i = 0; i < t.length; i++) {
            String ts = t[i].toUpperCase();
            if (ts.length() != 2)
                throw new AnalyzerException("Byte contains more than two hexadecimal digits", i);
            if (!HEXADECIMAL_DIGITS.contains(ts.substring(0, 1)))
                throw new AnalyzerException("The first digit of the byte is not hexadecimal", i);
            if (!HEXADECIMAL_DIGITS.contains(ts.substring(1, 2)))
                throw new AnalyzerException("The second digit of the byte is not hexadecimal", i);
        }
    }

    public static void checkTrace(String t) throws AnalyzerException {
        checkTrace(t.split(" "));
    }

    public String getName() {
        return name;
    }

    public String getNameCode() {
        return nameCode;
    }

    public String[] getT() {
        return t;
    }

    public String getProtocolName() {
        return protocolName;
    }

    public Map<String, String[]> getInformations() {
        return informations;
    }

    public String getRecap() {
        return name + " (" + nameCode + ")";
    }

    @Override
    public String toString() {
        String s = "\n--------------------------------------------------" +
                name + " (" + nameCode + ")";
        for (String key: informations.keySet()) {
            String[] value = informations.get(key);
            s += "\n" + key + " : " + value[0] + ((value[1].isEmpty()) ? "": " (" + value[1] + ")");
        }
        return s;
    }
}
