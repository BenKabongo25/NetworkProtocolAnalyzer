package model.analyzers.dhcp;

public enum OptionType {
    // unrecognized
    UNRECOGNIZED_OPTION(-1, OptionType.VARIABLE_LENGTH, "Unrecognized Option", OptionType.HEXA_VALUE),
    // Vendor extensions
    PadOption(0, 0, "Pad"),
    EndOption(255, 0, "End"),
    //
    SubnetMaskOption(1, 4, "Subnet Mask", OptionType.IP_VALUE),
    TimeOffsetOption(2, 4, "Time Offset"),
    RouterOption(3, OptionType.VARIABLE_LENGTH_4, "Router", OptionType.IP_VALUE),
    TimeServerOption(4, OptionType.VARIABLE_LENGTH_4, "Time Server", OptionType.IP_VALUE),
    NameServerOption(5, OptionType.VARIABLE_LENGTH_4, "Name Server", OptionType.IP_VALUE),
    DomainNameServerOption(6, OptionType.VARIABLE_LENGTH_4, "Domain Name Server", OptionType.IP_VALUE),
    LogServerOption(7, OptionType.VARIABLE_LENGTH_4, "Log Server", OptionType.IP_VALUE),
    CookieServerOption(8, OptionType.VARIABLE_LENGTH_4, "Cookie Server", OptionType.IP_VALUE),
    LPRServerOption(9, OptionType.VARIABLE_LENGTH_4, "LPR Server", OptionType.IP_VALUE),
    ImpressServerOption(10, OptionType.VARIABLE_LENGTH_4, "Impress Server", OptionType.IP_VALUE),
    ResourceLocationServerOption(11, OptionType.VARIABLE_LENGTH_4, "Resource Location Server", OptionType.IP_VALUE),
    HostNameOption(12, OptionType.VARIABLE_LENGTH, "Host Name", OptionType.STRING_VALUE),
    BootFileSizeOption(13, 2, "Boot File Size"),
    MeritDumpFileOption(14, OptionType.VARIABLE_LENGTH, "Merit Dump File", OptionType.STRING_VALUE),
    DomainNameOption(15, OptionType.VARIABLE_LENGTH, "Domain Name", OptionType.STRING_VALUE),
    SwapServerOption(16, 4, "Swap Server", OptionType.IP_VALUE),
    RootPathOption(17, OptionType.VARIABLE_LENGTH, "Root Path", OptionType.STRING_VALUE),
    ExtensionsPathOption(18, OptionType.VARIABLE_LENGTH, "Extensions Path", OptionType.STRING_VALUE),
    // IP Layer Parameters per Host
    IPForwardingEnableDisableOption(19, 1, "IP Forwarding Enable/Disable"),
    NonLocalSourceRoutingEnableDisableOption(20, 1, "Non-Local Source Routing Enable/Disable"),
    PolicyFilterOption(21, OptionType.VARIABLE_LENGTH_8, "Policy Filter", OptionType.IP_VALUE),
    MaximumDatagramReassemblySizeOption(22, 2, "Maximum Datagram Reassembly Size"),
    DefaultIPTimeToLiveOption(23, 1, "Default IP Time-to-live"),
    PathMTUAgingTimeoutOption(24, 4, "Path MTU Aging Timeout"),
    PathMTUPlateauTableOption(25, OptionType.VARIABLE_LENGTH_2, "Path MTU Plateau Table"),
    InterfaceMTUOption(26, 2, "Interface MTU"),
    AllSubnetsAreLocalOption(27, 1, "All Subnets are Local"),
    BroadcastAddressOption(28, 4, "Broadcast Address", OptionType.IP_VALUE),
    PerformMaskDiscoveryOption(29, 1, "Perform Mask Discovery"),
    MaskSupplierOption(30, 1, "Mask Supplier"),
    PerformRouterDiscoveryOption(31, 1, "Perform Router Discovery"),
    RouterSolicitationAddressOption(32, 4, "Router Solicitation Address", OptionType.IP_VALUE),
    StaticRouteOption(33, OptionType.VARIABLE_LENGTH_8, "Static Route", OptionType.IP_VALUE),
    // Link Layer Parameters per Interface
    TrailerEncapsulationOption(34, 1, "Trailer Encapsulation"),
    ARPCacheTimeoutOption(35, 4, "ARP Cache Timeout"),
    EthernetEncapsulationOption(36, 1, "Ethernet Encapsulation"),
    // TCP Parameters
    TCPDefaultTTLOption(37, 1, "TCP Default TTL"),
    TCPKeepaLiveIntervalOption(38, 4, "TCP Keepalive Interval"),
    TCPKeepaLiveGarbageOption(39, 1, "TCP Keepalive Garbage"),
    // Application and Service Parameters
    NetworkInformationServiceDomainOption(40, OptionType.VARIABLE_LENGTH, "Network Information Service Domain", OptionType.STRING_VALUE),
    NetworkInformationServersOption(41, OptionType.VARIABLE_LENGTH_4, "Network Information Servers", OptionType.IP_VALUE),
    NetworkTimeProtocolServersOption(42, OptionType.VARIABLE_LENGTH_4, "Network Time Protocol Servers", OptionType.IP_VALUE),
    VendorSpecificInformationOption(43, OptionType.VARIABLE_LENGTH, "Vendor Specific Information", OptionType.STRING_VALUE),
    NetBIOSOverTCPIPNameServerOption(44, OptionType.VARIABLE_LENGTH_4, "NetBIOS over TCP/IP Name Server", OptionType.IP_VALUE),
    NetBIOSOverTCPIPDatagramDistributionServerOption(45, OptionType.VARIABLE_LENGTH_4, "NetBIOS over TCP/IP Datagram Distribution Server", OptionType.IP_VALUE),
    NetBIOSOverTCPIPNodeTypeOption(46, 1, "NetBIOS over TCP/IP Node Type", OptionType.ENUM_VALUE),
    NetBIOSOverTCPIPScopeOption(47, OptionType.VARIABLE_LENGTH, "NetBIOS over TCP/IP Scope"),
    XWindowSystemFontServerOption(48, OptionType.VARIABLE_LENGTH_4, "X Window System Font Server", OptionType.IP_VALUE),
    XWindowSystemDisplayManagerOption(49, OptionType.VARIABLE_LENGTH_4, "X Window System Display Manager", OptionType.IP_VALUE),
    // DHCP Extensions
    RequestedIPAddressOption(50, 4, "Requested IP Address", OptionType.IP_VALUE),
    IPAddressLeaseTimeOption(51, 4, "IP Address Lease Time"),
    OverloadOption(52, 1, "Option Overload", OptionType.ENUM_VALUE),
    DHCPMessageTypeOption(53, 1, "DHCP Message Type", OptionType.ENUM_VALUE),
    ServerIdentifierOption(54, 4, "Server Identifier", OptionType.IP_VALUE),
    ParameterRequestListOption(55, OptionType.VARIABLE_LENGTH, "Parameter Request List", OptionType.LIST_VALUE),
    Message(56, OptionType.VARIABLE_LENGTH, "Message", OptionType.STRING_VALUE),
    MaximumDHCPMessageSize(57, 2, "Maximum DHCP Message Size"),
    RenewalTimeValue(58, 4, "Renewal (T1) Time Value"),
    RebindingTimeValue(59, 4, "Rebinding (T2) Time Value"),
    VendorClassIdentifier(60, OptionType.VARIABLE_LENGTH, "Vendor class identifier", OptionType.HEXA_VALUE),
    ClientIdentifier(61, OptionType.VARIABLE_LENGTH, "Client-identifier", OptionType.MAC_VALUE),
    //
    NetworkInformationServiceMoreDomainOption(64, OptionType.VARIABLE_LENGTH, "Network Information Service+ Domain", OptionType.STRING_VALUE),
    NetworkInformationServiceMoreServersOption(65, OptionType.VARIABLE_LENGTH, "Network Information Service+ Servers"),
    //
    TFTPServerName(66, OptionType.VARIABLE_LENGTH, "TFTP server name"),
    BootFileName(67, OptionType.VARIABLE_LENGTH, "Bootfile name", OptionType.STRING_VALUE),
    //
    MobileIPHomeAgentOption(68, OptionType.VARIABLE_LENGTH_4, "Mobile IP Home Agent", OptionType.IP_VALUE),
    SimpleMailTransportProtocolServerOption(69, OptionType.VARIABLE_LENGTH_4, "Simple Mail Transport Protocol (SMTP) Server", OptionType.IP_VALUE),
    PostOfficeProtocolServerOption(70, OptionType.VARIABLE_LENGTH_4, "Post Office Protocol (POP3) Server", OptionType.IP_VALUE),
    NetworkNewsTransportProtocolServerOption(71, OptionType.VARIABLE_LENGTH_4, "Network News Transport Protocol (NNTP) Server", OptionType.IP_VALUE),
    DefaultWorldWideWebServerOption(72, OptionType.VARIABLE_LENGTH_4, "Default World Wide Web (WWW) Server", OptionType.IP_VALUE),
    DefaultFingerServerOption(73, OptionType.VARIABLE_LENGTH_4, "Default Finger Server", OptionType.IP_VALUE),
    DefaultInternetRelayChatServerOption(74, OptionType.VARIABLE_LENGTH_4, "Default Internet Relay Chat (IRC) Server", OptionType.IP_VALUE),
    StreetTalkServerOption(75, OptionType.VARIABLE_LENGTH_4, "StreetTalk Server", OptionType.IP_VALUE),
    StreetTalkDirectoryAssistanceServerOption(76, OptionType.VARIABLE_LENGTH_4, "StreetTalk Directory Assistance (STDA) Server", OptionType.IP_VALUE),
    //
    UserClassOption(77, OptionType.VARIABLE_LENGTH, "User Class", OptionType.HEXA_VALUE),
    DirectoryAgentOption(78, OptionType.VARIABLE_LENGTH, "Directory Agent", OptionType.HEXA_VALUE),
    ServiceLocationAgentScopeOption(79, OptionType.VARIABLE_LENGTH, "Service Location Agent Scope", OptionType.HEXA_VALUE),
    RapidCommitOption(80, 0, "Rapid Commit"),
    ClientFullyQualifiedDomainNameOption(81, OptionType.VARIABLE_LENGTH, "Client Fully Qualified Domain Name (FQDN) Option", OptionType.HEXA_VALUE),
    // RelayAgentInformationOption(82, )


    ;

    private final int code;
    private final int length;
    private final String name;
    private final int valueType;

    // variables length multiples
    public static final int VARIABLE_LENGTH = -1;
    public static final int VARIABLE_LENGTH_2 = -2;
    public static final int VARIABLE_LENGTH_4 = -4;
    public static final int VARIABLE_LENGTH_8 = -8;

    // type of value
    public static final int NUMBER_VALUE = 0;
    public static final int STRING_VALUE = 1;
    public static final int IP_VALUE = 2;
    public static final int ENUM_VALUE = 3;
    public static final int LIST_VALUE = 4;
    public static final int MAC_VALUE = 5;
    public static final int HEXA_VALUE = 6;

    OptionType(int code, int length, String name, int valueType) {
        this.code = code;
        this.length = length;
        this.name = name;
        this.valueType = valueType;
    }

    OptionType(int code, int length, String name) {
        this(code, length, name, NUMBER_VALUE);
    }

    public int getCode() {
        return code;
    }

    public int getLength() {
        return length;
    }

    public String getName() {
        return name;
    }

    public int getValueType() {
        return valueType;
    }

    public static OptionType getOptionType(int code) {
        for (OptionType option: OptionType.values()) {
            if (option.code == code)
                return option;
        }
        return null;
    }
}
