package model.enums;

public enum HardwareAddressLength {
    UNRECOGNIZED(-1, "Unrecognized", "Unrecognized Hardware Address Length"),
    TokenRing(1, "Token Ring", "Token Ring"),
    Ethernet(6, "Ethernet", "Ethernet");

    private final int value;
    private final String name;
    private final String description;

    HardwareAddressLength(int value, String name, String description) {
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
