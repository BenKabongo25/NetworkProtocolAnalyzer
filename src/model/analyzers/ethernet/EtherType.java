package model.analyzers.ethernet;

import model.analyzers.SimpleAnalyzer;

/**
 * Base class of protocols contained in Ethernet II
 */
public abstract class EtherType extends SimpleAnalyzer {

    protected final Type type;

    public EtherType(String name, String nameCode, Type type, String[] t) {
        super(name, nameCode, t);
        this.type = type;
    }

    public EtherType(String name, String nameCode, Type type, String t) {
        super(name, nameCode, t);
        this.type = type;
    }
}
