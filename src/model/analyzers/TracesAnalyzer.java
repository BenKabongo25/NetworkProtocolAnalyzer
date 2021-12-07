package model.analyzers;

import model.analyzers.ethernet.EthernetAnalyzer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Multi-traces Analyzer
 */
public class TracesAnalyzer extends Analyzer {

    private final String t;
    private final boolean offset;
    private final List<EthernetAnalyzer> analyzers;
    private final Map<Integer, AnalyzerException> analyzersExceptions;

    public TracesAnalyzer(String t, boolean offset) {
        this.t = t;
        this.offset = offset;
        analyzers = new ArrayList<>();
        analyzersExceptions = new HashMap<>();
    }

    private void createAnalyzers() throws AnalyzerException {
        String[] lines = t.replace("\t", " ")
                .replace("  ", " ")
                .replace("  ", " ")
                .toLowerCase().trim().split("\n");
        if (!offset) {
            String trace = String.join(" ", lines);
            EthernetAnalyzer analyzer = new EthernetAnalyzer(trace);
            analyzers.add(analyzer);
        }
        else {
            String trace = "";
            int lastI = -1;
            int lastOffset = -1;
            int offset = 0;
            for (int i = 0; i <= lines.length; i++) {
                String line;
                if (i == lines.length)
                    offset = 0;
                else {
                    line = lines[i];
                    String[] words = line.split(" ");
                    try {
                        offset = Integer.parseInt(words[0], 16);
                    } catch (Exception e) {
                        continue;
                    }
                }
                if (offset == 0) {
                    if (lastI > -1) {
                        String lastLine = lines[lastI];
                        String[] lastWords = lastLine.split(" ");
                        int j;
                        for (j = 1; j < lastWords.length; j++) {
                            if (lastWords[j].trim().length() != 2)
                                break;
                            try {
                                Integer.parseInt(lastWords[j], 16);
                            } catch (Exception e) {
                                break;
                            }
                        }
                        trace += " " +String.join(" ", Arrays.copyOfRange(lastWords, 1, j));
                        analyzers.add(new EthernetAnalyzer(trace.trim()));
                        trace = "";
                    }
                }
                else {
                    int diff = offset - lastOffset + 1;
                    String lastLine = lines[lastI];
                    String[] lastWords = lastLine.split(" ");
                    if (lastWords.length < diff)
                        throw new AnalyzerException("The trace line does not contain enough bytes", lastI);
                    trace += " " + String.join(" ", Arrays.copyOfRange(lastWords, 1, diff));
                }
                lastI = i;
                lastOffset = offset;
            }
            if (!trace.trim().isEmpty())
                analyzers.add(new EthernetAnalyzer(trace.trim()));
        }
    }

    @Override
    public void analyze() throws AnalyzerException {
        createAnalyzers();
        for (int i = 0; i < analyzers.size(); i++) {
            EthernetAnalyzer analyzer = analyzers.get(i);
            try {
                SimpleAnalyzer.checkTrace(analyzer.getT());
                analyzer.analyze();
            } catch (AnalyzerException ae) {
                analyzersExceptions.put(i, ae);
            } catch (IndexOutOfBoundsException iobe) {
                AnalyzerException ae = new AnalyzerException("The number of bytes in the trace is insufficient", analyzer.getT().length);
                analyzersExceptions.put(i, ae);
            } catch (Exception e) {
                AnalyzerException ae = new AnalyzerException("ERROR : " + e.getMessage(), analyzer.getT().length);
                analyzersExceptions.put(i, ae);
            }
        }
    }

    public List<EthernetAnalyzer> getAnalyzers() {
        return analyzers;
    }

    public Map<Integer, AnalyzerException> getAnalyzersExceptions() {
        return analyzersExceptions;
    }
}
