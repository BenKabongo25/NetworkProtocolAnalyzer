package tests;

import model.analyzers.AnalyzerException;
import model.analyzers.SimpleAnalyzer;
import model.analyzers.ethernet.EthernetAnalyzer;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class SimpleAnalyzerMain {

    public static void main(String[] args) throws FileNotFoundException {
        if (args.length == 0) {
            System.out.println("You must pass the name of a file to be analyzed");
            return;
        }
        File file = new File(args[0]);
        String trace = "";
        Scanner scanner = new Scanner(file);
        while (scanner.hasNextLine())
            trace += scanner.nextLine() + " ";
        scanner.close();
        // System.out.println(trace);
        try {
            SimpleAnalyzer.checkTrace(trace);
        } catch (AnalyzerException e) {
            System.out.println("ERROR : " + e.getMessage());
            System.out.println("AT Byte number : " + e.getByteNumber());
        }

        EthernetAnalyzer analyzer = new EthernetAnalyzer(trace);
        try {
            analyzer.analyze();
            System.out.println(analyzer);
        } catch (AnalyzerException e) {
            System.out.println("ERROR : " + e.getMessage());
            System.out.println("AT Byte number : " + e.getByteNumber());
        }
    }
}
