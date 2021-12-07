package model.analyzers.dns;

public enum OpCode {
    UNRECONGIZED_CODE(-1, "URECOGNIZED", "Unrecognized Operation Code"),
    QUERY(0, "QUERY", "Standard Query"),
    IQUERY(1, "IQUERY", "Inverse Query"),
    STATUS(2, "STATUS", "Server Status Request"),
    NOTIFY(4, "NOTIFY", "Database update notification"),
    UPDATE(5, "UDPDATE", "Dynamic database update"),
    OPCODE_6(6, "UNRECOGNIZED", "Code not  assigned"),
    OPCODE_7(7, "UNRECOGNIZED", "Code not  assigned"),
    OPCODE_8(8, "UNRECOGNIZED", "Code not  assigned"),
    OPCODE_9(9, "UNRECOGNIZED", "Code not  assigned"),
    OPCODE_10(10, "UNRECOGNIZED", "Code not  assigned"),
    OPCODE_11(11, "UNRECOGNIZED", "Code not  assigned"),
    OPCODE_12(12, "UNRECOGNIZED", "Code not  assigned"),
    OPCODE_13(13, "UNRECOGNIZED", "Code not  assigned"),
    OPCODE_14(14, "UNRECOGNIZED", "Code not  assigned"),
    OPCODE_15(15, "UNRECOGNIZED", "Code not  assigned");

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

    public static OpCode getOpCode(int value) {
        for (OpCode opCode: OpCode.values()) {
            if (opCode.value == value)
                return opCode;
        }
        return null;
    }

    @Override
    public String toString() {
        return name + "(" + value + ")";
    }
}
