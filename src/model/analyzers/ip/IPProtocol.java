package model.analyzers.ip;

import model.analyzers.SimpleAnalyzer;

public abstract class IPProtocol extends SimpleAnalyzer {

    protected final IPProtocolType type;

    public IPProtocol(String name, String nameCode, IPProtocolType type, String[] t) {
        super(name, nameCode, t);
        this.type = type;
    }

    public IPProtocol(String name, String nameCode, IPProtocolType type, String t) {
        super(name, nameCode, t);
        this.type = type;
    }
}
