package model.analyzers.ethernet;

/**
 * Type of EtherType
 */
public enum Type {
    IPv4("IPv4", "0800", "Internet Protocol Version 4"),
    IPv6("IPv6", "86dd", "Internet Protocol Version 6"),
    ARP("ARP", "0806", "Address Resolution Protocol");

    private final String name;
    private final String value;
    private final String description;

    Type(String name, String value, String description) {
        this.name = name;
        this.value = value;
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return name + " (0x" + value + ")";
    }
}