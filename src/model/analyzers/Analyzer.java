package model.analyzers;

/**
 * Base class of analyzers
 */
public abstract class Analyzer {

   /**
    * All analyzers implement this analysis method
    * @throws AnalyzerException raised when an analysis error is detected
    */
   public abstract void analyze() throws AnalyzerException;
}
