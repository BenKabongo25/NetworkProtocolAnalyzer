package model.analyzers.tcp;

public enum OptionType {
    UNRECOGNIZED_OPTION(-1, 0, "Unrecognized Option", ""),
    EndOfOptionList(0, 1, "End of Option List", "RFC793"),
    NoOperation(1, 1, "No-Operation", "RFC793"),
    MaximumSegmentSize(2, 4, "Maximum Segment Size", "RFC793"),
    WindowScale(3, 3, "Window Scale",	"RFC7323"),
    SackPermitted(4, 2, "SACK Permitted", "RFC2018"),
    Sack(5, -1,	"SACK",	"RFC2018"),
    Echo(6, 6, "Echo", "RFC1072, RFC6247"),
    EchoReply(7, 6, "Echo Reply", "RFC1072, RFC6247"),
    Timestamps(8, 10, "Timestamps",	"RFC7323"),
    PartialOrderConnectionPermitted(9, 2, "Partial Order Connection Permitted", "RFC1693, RFC6247"),
    PartialOrderServiceProfile(10, 3, "Partial Order Service Profile", "RFC1693, RFC6247"),
    CC(11, 1, "CC",	"RFC1644, RFC6247"),
    CCNew(12, 1, "CC.NEW", "RFC1644, RFC6247"),
    CCEcho(13, 1, "CC.ECHO", "RFC1644, RFC6247"),
    TCPAlternateChecksumRequest(14, 3, "TCP Alternate Checksum Request", "RFC1146, RFC6247"),
    TCPAlternateChecksumData(15, -1, "TCP Alternate Checksum Data", "RFC1146, RFC6247"),
    Skeeter(16, 1, "Skeeter", "Stev_Knowles"),
    Bubba(17, 1, "Bubba", "Stev_Knowles"),
    TrailerChecksumOption(18, 3, "Trailer Checksum Option",	"Subbu_Subramaniam, Monroe_Bridges"),
    MD5SignatureOption(19, 18, "MD5 Signature Option", "RFC2385"),
    SCPSCapabilities(20, 1,	"SCPS Capabilities", "Keith_Scott"),
    SelectiveNegativeAcknowledgements(21, 1, "Selective Negative Acknowledgements", "Keith_Scott"),
    RecordBoundaries(22, 1, "Record Boundaries", "Keith_Scott"),
    Corruption(23, 1, "Corruption",	"Keith_Scott"),
    SNAP(24, 1, "SNAP",	"Vladimir_Sukonnik"),
    Unassigned(25, 1, "Unassigned",  ""),
    TCPCompressionFilter(26, 1,	"TCP Compression Filter", "Steve_Bellovin"),
    QuickStartResponse(27, 8,"Quick-Start Response", "RFC4782"),
    UserTimeoutOption(28, 4,"User Timeout Option", "RFC5482"),
    TCPAuthenticationOption(29, 1,	"TCP Authentication Option (TCP-AO)", "RFC5925"),
    MultipathTCP(30, -1, "Multipath TCP (MPTCP)", "RFC8684"),
    TCPFastOpenCookie(34, -2, "TCP Fast Open Cookie", "RFC7413"),
    EncryptionNegotiation(69, -1,"Encryption Negotiation (TCP-ENO)", "RFC8547")
    ;

    private final int kind;
    private final int length; // N = -1, variable = -2
    private final String meaning;
    private final String reference;

    OptionType(int kind, int length, String meaning, String reference) {
        this.kind = kind;
        this.length = length;
        this.meaning = meaning;
        this.reference = reference;
    }

    public int getKind() {
        return kind;
    }

    public int getLength() {
        return length;
    }

    public String getMeaning() {
        return meaning;
    }

    public String getReference() {
        return reference;
    }

    @Override
    public String toString() {
        return meaning + "(kind=" + kind + ", length=" + length + ")";
    }

    public static OptionType getOptionType(int kind) {
        for (OptionType optionType : OptionType.values()) {
            if (optionType.kind == kind)
                return optionType;
        }
        return null;
    }
}