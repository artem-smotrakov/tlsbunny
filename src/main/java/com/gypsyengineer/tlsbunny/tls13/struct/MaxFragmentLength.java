package com.gypsyengineer.tlsbunny.tls13.struct;

import com.gypsyengineer.tlsbunny.tls.Struct;

/**
 * See RFC 6066
 */
public interface MaxFragmentLength extends Struct {

    int encoding_length = 1;

    MaxFragmentLength two_pow_nine = StructFactory.getDefault().createMaxFragmentLength(1);
    MaxFragmentLength two_pow_ten = StructFactory.getDefault().createMaxFragmentLength(2);
    MaxFragmentLength two_pow_eleven = StructFactory.getDefault().createMaxFragmentLength(3);
    MaxFragmentLength two_pos_twelve = StructFactory.getDefault().createMaxFragmentLength(4);

    int getCode();

    static MaxFragmentLength[] values() {
        return new MaxFragmentLength[] {
                two_pow_nine,
                two_pow_ten,
                two_pow_eleven,
                two_pos_twelve
        };
    }

    static int[] codes() {
        return new int[] {
                two_pow_nine.getCode(),
                two_pow_ten.getCode(),
                two_pow_eleven.getCode(),
                two_pos_twelve.getCode()
        };
    }
}
