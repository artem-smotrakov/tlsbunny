package com.gypsyengineer.tlsbunny.fuzzer;

import java.util.BitSet;
import java.util.HashSet;
import java.util.Set;

public class BitFlipFuzzer extends AbstractFlipFuzzer {

    public static BitFlipFuzzer bitFlipFuzzer() {
        return new BitFlipFuzzer(
                default_min_ratio, default_max_ratio,
                from_the_beginning, not_specified);
    }

    public static BitFlipFuzzer bitFlipFuzzer(double ratio) {
        return new BitFlipFuzzer(ratio, ratio, from_the_beginning, not_specified);
    }

    public BitFlipFuzzer(double ratio) {
        super(ratio, ratio, from_the_beginning, not_specified);
    }

    public BitFlipFuzzer(double minRatio, double maxRatio, int start, int end) {
        super(minRatio, maxRatio, start, end);
    }

    @Override
    protected byte[] fuzzImpl(byte[] array) {
        check(minRatio, maxRatio);

        BitSet bits = BitSet.valueOf(array);
        double ratio = getRatio();
        int start = getStartIndex();
        int end = getEndIndex(array);
        int startBit = start * 8;
        int endBit = (end + 1 ) * 8;
        int n = (int) Math.ceil((endBit - startBit) * ratio);

        // make sure that we fuzz at least one bit
        if (n == 0) {
            n = 1;
        }

        Set<Integer> processed = new HashSet<>();
        int i = 0;
        while (i < n) {
            int pos = startBit + random.nextInt(endBit - startBit);

            if (processed.contains(pos)) {
                continue;
            }

            bits.flip(pos);
            processed.add(pos);
            i++;
        }

        return bits.toByteArray();
    }

}
