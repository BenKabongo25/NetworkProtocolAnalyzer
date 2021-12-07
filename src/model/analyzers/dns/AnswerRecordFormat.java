package model.analyzers.dns;

public class AnswerRecordFormat extends RecordFormat {

    protected final long TTL;
    protected final int dataLength;
    protected final String data;

    public AnswerRecordFormat(String name, int typeCode, int classCode, long TTL, int dataLength, String data) {
        super(name, typeCode, classCode);
        this.TTL = TTL;
        this.dataLength = dataLength;
        this.data = data;
    }

    public long getTTL() {
        return TTL;
    }

    public int getDataLength() {
        return dataLength;
    }

    public String getData() {
        return data;
    }
}
