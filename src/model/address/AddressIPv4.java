package model.address;

import model.address.Address;

public class AddressIPv4 extends Address {

    /**
     * IPv4 Address
     * @param values 4 fields (0 - 255)
     */
    public AddressIPv4(String[] values) {
        super(4, values);
    }

    public AddressIPv4(String a, String b, String c, String d) {
        this(new String[]{a, b, c, d});
    }

    public AddressIPv4(int a, int b, int c, int d) {
        this(new String[]{String.valueOf(a), String.valueOf(b), String.valueOf(c), String.valueOf(d)});
    }

    @Override
    public String toString() {
        return values[0] + "." + values[1] + "." + values[2] + "." + values[3];
    }
}
