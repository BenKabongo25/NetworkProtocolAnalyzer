package model.analyzers.dns;

public enum Class {
    UNRECOGNIZED_CLASS(-1, "Unrecognized class", ""),
    IN(1, "IN", "")
    ;

    private final int value;
    private final String name;
    private final String description;

    Class(int value, String name, String description) {
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

    public static Class getClass(int value) {
        for (Class class_ : Class.values()) {
            if (class_.value == value)
                return class_;
        }
        return null;
    }

    @Override
    public String toString() {
        return name + ((this == UNRECOGNIZED_CLASS) ? "" : "(" + value + ")");
    }
}