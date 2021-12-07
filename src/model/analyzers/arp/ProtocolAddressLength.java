package model.analyzers.arp;

public enum ProtocolAddressLength {
    IPv4(4, "IPv4", "Internet Protocol Version 4"),
    IPv6(16, "IPv6", "Internet Protocol Version 6");

    private final int value;
    private final String name;
    private final String description;

    ProtocolAddressLength(int value, String name, String description) {
        this.value = value;
        this.name = name;
        this.description = description;
    }

    public int getValue() {
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
        return name + "(" + value + ")";
    }
}