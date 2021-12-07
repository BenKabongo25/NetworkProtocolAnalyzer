package model.address;

import java.util.Arrays;

/**
 * Base class of addresses
 */
public abstract class Address {

    /**
     *  values of address
     */
    protected String[] values;

    /**
     * Address
     * @param cardinal number of fields
     * @param values values of fields
     */
    public Address(int cardinal, String[] values) {
        assert values.length == cardinal;
        this.values = values;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Address adress = (Address) o;
        return Arrays.equals(values, adress.values);
    }
}
