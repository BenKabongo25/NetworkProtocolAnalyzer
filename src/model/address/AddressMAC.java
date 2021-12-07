package model.address;

import model.address.Address;

public class AddressMAC extends Address {

    /**
     * MAC Address
     * @param values 6 fields (from 00 to FF)
     */
    public AddressMAC(String[] values) {
        super(6, values);
    }

    public AddressMAC(String a, String b, String c, String d, String e, String f) {
        this(new String[]{a, b, c, d, e, f});
    }

    public boolean isBroadcast() {
        return toString().toLowerCase().equals("ff:ff:ff:ff:ff:ff");
    }

    @Override
    public String toString() {
        return values[0] + ":" + values[1] + ":" + values[2] + ":" + values[3] + ":" + values[4] + ":" + values[5];
    }
}
