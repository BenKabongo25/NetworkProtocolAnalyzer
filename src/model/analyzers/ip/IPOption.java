package model.analyzers.ip;

import model.address.AddressIPv4;

import java.util.ArrayList;
import java.util.List;

public class IPOption {

    protected OptionType type;
    protected int size;
    protected List<AddressIPv4> iPv4Adress;

    public IPOption(OptionType type, int size, List<AddressIPv4> iPv4Adress) {
        this.type = type;
        this.size = size;
        this.iPv4Adress = iPv4Adress;
    }

    public IPOption(OptionType type, int size) {
        this(type, size, new ArrayList<>());
    }

    public OptionType getOptionType() {
        return type;
    }

    public int getSize() {
        return size;
    }

    public List<AddressIPv4> getiPv4Adress() {
        return iPv4Adress;
    }
}
