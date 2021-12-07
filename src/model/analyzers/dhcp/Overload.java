package model.analyzers.dhcp;

/**
 * Values of option DHCP Option Overload
 */
public enum Overload {
    UNRECOGNIZED(-1, "Unrecognized value"),
    ONE(1, "The 'file' field is used to hold options"),
    TWO(2, "The 'sname' field is used to hold options"),
    TREE(3, "Both fields are used to hold options");

    private final int value;
    private final String meaning;

    Overload(int value, String meaning) {
        this.value = value;
        this.meaning = meaning;
    }

    public int getValue() {
        return value;
    }

    public String getMeaning() {
        return meaning;
    }

    public static Overload getOptionOverload(int value) {
        for (Overload overload: Overload.values()) {
            if (overload.value == value)
                return overload;
        }
        return null;
    }
}