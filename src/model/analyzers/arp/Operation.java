package model.analyzers.arp;

public enum Operation {
    Unrecognized(-1, "Unrecognized", "Unrecognized Operation"),
    Request(1, "Request", "Request Operation"),
    Reply(2, "Reply", "Reply Operation");

    private final int value;
    private final String name;
    private final String description;

    Operation(int value, String name, String description) {
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
