package tests;

import model.analyzers.AnalyzerException;
import model.analyzers.TracesAnalyzer;
import model.analyzers.ethernet.EthernetAnalyzer;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class TracesAnalyzerMain {

    public static void main(String[] args) throws FileNotFoundException {
        if (args.length == 0) {
            System.out.println("You must pass the name of a file to be analyzed");
            return;
        }
        File file = new File(args[0]);
        String trace = "";
        Scanner scanner = new Scanner(file);
        while (scanner.hasNextLine())
            trace += scanner.nextLine() + "\n";
        scanner.close();

        TracesAnalyzer tracesAnalyzer = new TracesAnalyzer(trace, true);
        try {
            tracesAnalyzer.analyze();
        } catch (AnalyzerException ignored) {
        }

        for (int i = 0; i < tracesAnalyzer.getAnalyzers().size(); i++) {
            System.out.print("Frame number " + (i+1));
            EthernetAnalyzer analyzer = tracesAnalyzer.getAnalyzers().get(i);
            System.out.println(analyzer);
            AnalyzerException analyzerException = null;
            if (tracesAnalyzer.getAnalyzersExceptions().containsKey(i)) {
                analyzerException = tracesAnalyzer.getAnalyzersExceptions().get(i);
                System.out.println("ERROR " + analyzerException.getMessage());
                System.out.println("AT " + analyzerException.getByteNumber());
            }
        }
    }
}
