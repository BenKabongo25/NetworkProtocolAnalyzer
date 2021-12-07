package model.analyzers.dhcp;

public enum OpCode {
    UNRECOGNIZED(-1, "Unrecognized", "Unrecognized Operation Code"),
    BOOT_REQUEST(1, "Boot request", "Client request"),
    BOOT_REPLY(2, "Boot reply", "Server reply");

    private final int value;
    private final String name;
    private final String description;

    OpCode(int value, String name, String description) {
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

