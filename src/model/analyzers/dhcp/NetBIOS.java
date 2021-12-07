package model.analyzers.dhcp;

/**
 * Values of option DHCP NetBIOS
 */
public enum NetBIOS {
    UNRECOGNIZED(-1, "Unrecognized value"),
    BNode(1, "B-Node"),
    PNode(2, "P-Node"),
    MNode(3, "M-Node"),
    HNode(4, "H-Node");

    private final int value;
    private final String name;

    NetBIOS(int value, String name) {
        this.value = value;
        this.name = name;
    }

    public int getValue() {
        return value;
    }

    public String getName() {
        return name;
    }

    public static NetBIOS getNetBIOS(int value) {
        for (NetBIOS netBIOS: NetBIOS.values()) {
            if (netBIOS.value == value)
                return netBIOS;
        }
        return null;
    }
}
