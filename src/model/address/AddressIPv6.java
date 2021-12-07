package model.address;

import model.address.Address;

public class AddressIPv6 extends Address {

    /**
     * IPv6 Address
     * @param values 8 fields (from 0000 to FFFF)
     */
    public AddressIPv6(String[] values) {
        super(8, values);
    }

    public AddressIPv6(String a, String b, String c, String d, String e, String f, String g, String h) {
        this(new String[]{a, b, c, d, e, f, g, h});
    }

    @Override
    public String toString() {
        return values[0] + ":" + values[1] + ":" + values[2] + ":" + values[3] + ":" + values[4] + ":" + values[5] + ":" + values[6] + ":" + values[7];
    }
}
