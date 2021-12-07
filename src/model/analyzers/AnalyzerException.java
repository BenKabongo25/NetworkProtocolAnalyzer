package model.analyzers;

/**
 * Analysis error manager
 */
public class AnalyzerException extends Exception {

    /**
     * Number of the byte in error
     */
    private int byteNumber = -1;

    public AnalyzerException(String message) {
        super(message);
    }

    public AnalyzerException(String message, int byteNumber) {
        super(message);
        this.byteNumber = byteNumber;
    }

    public int getByteNumber() {
        return byteNumber;
    }

    public void setByteNumber(int byteNumber) {
        this.byteNumber = byteNumber;
    }
}
