package model.analyzers.dhcp;

public class DHCPOption<T> {

    private final OptionType optionType;
    private final int code;
    private final int length;
    private final T value;

    public DHCPOption(OptionType optionType, int code,  int length, T value) {
        this.optionType = optionType;
        this.code = code;
        this.length = length;
        this.value = value;
    }

    public DHCPOption(OptionType optionType, int code, int length) {
        this(optionType, code,  length, null);
    }

    public DHCPOption(OptionType optionType) {
        this(optionType, optionType.getCode(), 0, null);
    }

    public OptionType getOptionType() {
        return optionType;
    }

    public int getCode() {
        return code;
    }

    public int getLength() {
        return length;
    }

    public T getValue() {
        return value;
    }
}
