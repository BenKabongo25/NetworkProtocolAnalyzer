package model.analyzers.dns;

public enum RCode {
    UNRECOGNIZED_CODE(-1, "Unrecognized", "Unrecognized code"),
    NoError(0, "NoError", "No Error"),
    FormErr(1, "FormErr", "Format Error"),
    ServFail(2, "ServFail", "Server Failure"),
    NXDomain(3, "NXDomain", "Non-Existent Domain"),
    NotImp(4, "NotImp", "Not Implemented"),
    Refused(5, "Refused", "Query Refused"),
    YXDomain(6, "YXDomain", "Name Exists when it should not"),
    YXRRSet(7, "YXRRSet", "RR Set Exists when it should not"),
    NXRRSet(8, "NXRRSet", "RR Set that should exist does not"),
    NotAuth(9, "NotAuth", "Server Not Authoritative for zone"),
    NotZone(10, "NotZone", "Name not contained in zone"),
    BADVERS(16, "BADVERS", "Bad OPT Version"),
    BADSIG(16, "BADSIG", "TSIG Signature Failure"),
    BADKEY(17, "BADKEY", "Key not recognized"),
    BADTIME(18, "BADTIME", "Signature out of time window"),
    BADMODE(19, "BADMODE", "Bad TKEY Mode"),
    BADNAME(20, "BADNAME", "Duplicate key name"),
    BADALG(21, "BADALG", "Algorithm not supported"),
    //...
    ;

    private final int value;
    private final String name;
    private final String description;

    RCode(int value, String name, String description) {
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

    public static RCode getRCode(int value) {
        for (RCode code: RCode.values()) {
            if (code.value == value)
                return code;
        }
        return null;
    }

    @Override
    public String toString() {
        return name + ((this == UNRECOGNIZED_CODE) ? "" : "(" + value + ")");
    }
}
