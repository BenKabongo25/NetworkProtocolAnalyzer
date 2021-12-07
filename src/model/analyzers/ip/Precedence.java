package model.analyzers.ip;

public enum Precedence {
    Routine(0, "Routine"),
    Priority(1, "Priority"),
    Immediate(2, "Immediate"),
    Flash(3, "Flash"),
    FlashOverride(4, "Flash Override"),
    CRITIC_ECP(5, "CRITIC/ECP"),
    InternetworkControl(6, "Internetwork Control"),
    NetworkControl(7, "Network Control");

    private final int value;
    private final String name;

    Precedence(int value, String name) {
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

    public static Precedence getPrecedence(int value) {
        for (Precedence precedence: values()) {
            if (precedence.value == value)
                return precedence;
        }
        return null;
    }
}
