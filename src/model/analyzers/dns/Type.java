package model.analyzers.dns;

public enum Type {
    UNRECOGNIZED_TYPE(-1, "Unrecognized type", "Unrecognized type"),
    A(1, "A", "IPv4 address"),
    NS(2, "NS", "Name Server"),
    CNAME(5, "CNAME", "Canonical Name"),
    SOA(6, "SOA", "Start of Authority"),
    WKS(7, "WKS", "Well Known Service"),
    MX(15, "MX", "MX Record"),
    AAAA(28, "AAAA", "IPv6 address")
    // ...
    ;

    private final int value;
    private final String name;
    private final String description;

    Type(int value, String name, String description) {
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

    public static Type getType(int value) {
        for (Type type: Type.values()) {
            if (type.value == value)
                return type;
        }
        return null;
    }

    @Override
    public String toString() {
        return name + ((this == UNRECOGNIZED_TYPE) ? "" : "(" + value + ")");
    }
}
