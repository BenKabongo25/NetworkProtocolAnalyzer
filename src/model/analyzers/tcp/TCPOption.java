package model.analyzers.tcp;

public class TCPOption {

    private final OptionType optionType;
    private final int kind;
    private final int length;
    private final String value;

    public TCPOption(OptionType optionType, int kind, int length, String value) {
        this.optionType = optionType;
        this.kind = kind;
        this.length = length;
        this.value = value;
    }

    public OptionType getOptionType() {
        return optionType;
    }

    public int getKind() {
        return kind;
    }

    public int getLength() {
        return length;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        final String s = (value.isEmpty()) ? "" : ", value=" + value;
        if (optionType != OptionType.UNRECOGNIZED_OPTION)
            return  optionType + s;
        return OptionType.UNRECOGNIZED_OPTION.getMeaning() + "(kind=" + kind + ", length=" + length + ")" + s;
    }
}
