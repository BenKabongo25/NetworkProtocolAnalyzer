package model.analyzers.ip;

public enum IPProtocolType {
    ICMP ("ICMP", "01", "Internet Control Message Protocol"),
    TCP ("TCP", "06", "Transmission Control Protocol"),
    UDP ("UDP", "11", "User Datagram Protocol");

    private final String name;
    private final String value;
    private final String description;

    IPProtocolType(String name, String value, String description) {
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

