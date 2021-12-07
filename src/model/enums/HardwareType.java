package model.enums;

public enum HardwareType {
    UNRECOGNIZED(-1, "Unrecognized", "Unrecognized Hardware Type"),
    Ethernet(1, "Ethernet", "01 - Ethernet (10Mb) [JBP]"),
    ExperimentalEthernet(2, "Experimental Ethernet", "02 - Experimental Ethernet (3Mb) [JBP]");

    private final int value;
    private final String name;
    private final String description;

    HardwareType(int value, String name, String description) {
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
