package model.analyzers.icmp;

public enum ICMPType {
    // source : Wikipedia ICMP
    ECHO_REPLY(0, 0, "Echo Reply", "Echo reply (used to ping)"),
    ECHO_REQUEST(8, 0, "Echo Request", "Echo request (used to ping)"),

    // Type = 3
    DESTINATION_UNREACHABLE_0(3, 0, "Destination Unreachable", "Destination network unreachable"),
    DESTINATION_UNREACHABLE_1(3, 1, "Destination Unreachable", "Destination host unreachable"),
    DESTINATION_UNREACHABLE_2(3, 2, "Destination Unreachable", "Destination protocol unreachable"),
    DESTINATION_UNREACHABLE_3(3, 3, "Destination Unreachable", "Destination port unreachable"),
    DESTINATION_UNREACHABLE_4(3, 4, "Destination Unreachable", "Fragmentation required, and DF flag set"),
    DESTINATION_UNREACHABLE_5(3, 5, "Destination Unreachable", "Source route failed"),
    DESTINATION_UNREACHABLE_6(3, 6, "Destination Unreachable", "Destination network unknown"),
    DESTINATION_UNREACHABLE_7(3, 7, "Destination Unreachable", "Destination host unknown"),
    DESTINATION_UNREACHABLE_8(3, 8, "Destination Unreachable", "Source host isolated"),
    DESTINATION_UNREACHABLE_9(3, 9, "Destination Unreachable", "Network administratively prohibited"),
    DESTINATION_UNREACHABLE_10(3, 10, "Destination Unreachable", "Host administratively prohibited"),
    DESTINATION_UNREACHABLE_11(3, 11, "Destination Unreachable", "Network unreachable for ToS"),
    DESTINATION_UNREACHABLE_12(3, 12, "Destination Unreachable", "Host unreachable for ToS"),
    DESTINATION_UNREACHABLE_13(3, 13, "Destination Unreachable", "Communication administratively prohibited"),
    DESTINATION_UNREACHABLE_14(3, 14, "Destination Unreachable", "Host Precedence Violation"),
    DESTINATION_UNREACHABLE_15(3, 15, "Destination Unreachable", "Precedence cutoff in effect"),

    SOURCE_QUENCH(4, 0, "Source Quench", "Source quench (congestion control)"),

    // Type 5
    REDIRECT_MESSAGE_0(5, 0, "Redirect Message", "Redirect Datagram for the Network"),
    REDIRECT_MESSAGE_1(5, 1, "Redirect Message", "Redirect Datagram for the Host"),
    REDIRECT_MESSAGE_2(5, 2, "Redirect Message", "Redirect Datagram for the ToS & network"),
    REDIRECT_MESSAGE_3(5, 3, "Redirect Message", "Redirect Datagram for the ToS & host"),

    ROUTER_ADVERTISEMENT(9, 0, "Router Advertisement", "Router Advertisement"),

    ROUTER_SOLICITATION(10, 0, "Router Solicitation", "Router discovery/selection/solicitation"),

    // Type 11
    TIME_EXCEEDED_0(11, 0, "Time Exceeded", "TTL expired in transit"),
    TIME_EXCEEDED_1(11, 0, "Time Exceeded", "Fragment reassembly time exceeded"),

    // Type 12
    PARAMETER_PROBLEM_0(12, 0, "Parameter Problem: Bad IP header", "Pointer indicates the error"),
    PARAMETER_PROBLEM_1(12, 1, "Parameter Problem: Bad IP header", "Missing a required option"),
    PARAMETER_PROBLEM_2(12, 2, "Parameter Problem: Bad IP header", "Bad length"),

    TIMESTAMP(13, 0, "Time Stamp", "Timestamp"),
    TIMESTAMP_REPLY(14, 0, "Timestamp Reply", "Timestamp Reply"),

    INFORMATION_REQUEST(15, 0, "Information Request", "Information Request"),
    INFORMATION_REPlY(16, 0, "Information Reply", "Information Reply"),

    ADDRESS_MASK_REQUEST(17, 0, "Address Mask Request", "Address Mask Request"),
    ADDRESS_MASK_REPLY(18, 0, "Address Mask Reply", "Address Mask Reply"),

    THROUGH29(20, 0, "Through 29", "Reserved for robustness experiment"),

    TRACEROUTE(30, 0, "Traceroute", "Information Request"),

    EXTENDED_ECHO_REQUEST(42, 0, "Extended Echo Request", "Request Extended Echo (XPing)"),

    // Type 43
    EXTENDED_ECHO_REPLY_0(43, 0, "Extended Echo Reply", "No Error"),
    EXTENDED_ECHO_REPLY_1(43, 1, "Extended Echo Reply", "Malformed Query"),
    EXTENDED_ECHO_REPLY_2(43, 2, "Extended Echo Reply", "No Such Interface"),
    EXTENDED_ECHO_REPLY_3(43, 3, "Extended Echo Reply", "No Such Table Entry"),
    EXTENDED_ECHO_REPLY_4(43, 4, "Extended Echo Reply", "Multiple Interfaces Satisfy Query");

    private final int type;
    private final int code;
    private final String name;
    private final String description;

    ICMPType(int type, int code, String name, String description) {
        this.type = type;
        this.code = code;
        this.name = name;
        this.description = description;
    }

    public int getType() {
        return type;
    }

    public int getCode() {
        return code;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return "ICMP(Type=" + type + ", Code=" + code;
    }

    public static ICMPType getICMPType(int type, int code) {
        for (ICMPType icmpType : ICMPType.values()) {
            if (icmpType.type == type && icmpType.code == code)
                return icmpType;
        }
        return null;
    }
}