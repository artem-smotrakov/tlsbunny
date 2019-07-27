package com.gypsyengineer.tlsbunny.fuzzer;

import java.util.HashSet;
import java.util.Set;

public class ByteFlipFuzzer extends AbstractFlipFuzzer implements Fuzzer<byte[]> {

    public static ByteFlipFuzzer newByteFlipFuzzer() {
        return new ByteFlipFuzzer();
    }

    public ByteFlipFuzzer() {
        super();
    }

    public ByteFlipFuzzer(double minRatio, double maxRatio, int start, int end) {
        super(minRatio, maxRatio, start, end);
    }

    @Override
    protected byte[] fuzzImpl(byte[] array) {
        check(minRatio, maxRatio);

        byte[] fuzzed = array.clone();
        double ratio = getRatio();
        int start = getStartIndex();
        int end = getEndIndex(array);
        int n = (int) ((end - start) * ratio);

        // make sure what we fuzz at least one byte
        if (n == 0) {
            n = 1;
        }

        Set<Integer> processed = new HashSet<>();
        int i = 0;
        while (i < n) {
            int pos = start + random.nextInt(end - start + 1);

            if (processed.contains(pos)) {
                continue;
            }

            fuzzed[pos] = (byte) random.nextInt(256);
            processed.add(pos);
            i++;
        }

        return fuzzed;
    }

}
