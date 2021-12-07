package model.analyzers.arp;

public enum ProtocolType {
    IP("0800", "IPv4", "Internet Protocol");

    private final String value;
    private final String name;
    private final String description;

    ProtocolType(String value, String name, String description) {
        this.value = value;
        this.name = name;
        this.description = description;
    }

    public String getValue() {
        return value;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return name + "(0x" + value + ")";
    }
}