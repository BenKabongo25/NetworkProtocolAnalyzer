package model.analyzers.dhcp;

/**
 * Values of option DHCP Message Type
 */
public enum DHCPMessageType {
    UNRECOGNIZED(-1, "Unrecognized value"),
    DHCP_DISCOVER(1, "DHCP DISCOVER"),
    DHCP_OFFER(2, "DHCP OFFER"),
    DHCP_REQUEST(3, "DHCP REQUEST"),
    DHCP_DECLINE(4, "DHCP DECLINE"),
    DHCP_ACK(5, "DHCP ACK"),
    DHCP_NAK(6, "DHCP NAK"),
    DHCP_RELEASE(7, "DHCP RELEASE"),
    DHCP_INFORM(8, "DHCP INFORM");

    private final int value;
    private final String name;

    DHCPMessageType(int value, String name) {
        this.value = value;
        this.name = name;
    }

    public int getValue() {
        return value;
    }

    public String getName() {
        return name;
    }

    public static DHCPMessageType getDHCPMessageType(int value) {
        for (DHCPMessageType message: DHCPMessageType.values()) {
            if (message.value == value)
                return message;
        }
        return null;
    }
}
