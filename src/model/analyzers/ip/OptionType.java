package model.analyzers.ip;

public enum OptionType {
    EOL (0, "End of Options List"),
    NO (1, "No Operation"),
    RR (7, "Record Route"),
    TS (68, "Time Stamp"),
    LR (131, "Loose Routing"),
    SR (138, "Strict Routing");

    private final int value;
    private final String name;

    OptionType(int value, String name) {
        this.value = value;
        this.name = name;
    }

    public int getValue() {
        return value;
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return name + " (" + value + ")";
    }
}

