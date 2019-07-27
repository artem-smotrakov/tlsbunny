package com.gypsyengineer.tlsbunny.tls;

import com.gypsyengineer.tlsbunny.utils.Converter;
import com.gypsyengineer.tlsbunny.utils.Utils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public interface Vector<T> extends Struct {

    interface ContentParser<T> {
        T parse(ByteBuffer buffer);
    }

    int size();
    boolean isEmpty();
    T get(int index);
    T first();
    void add(T object);
    void set(int index, T object);
    void clear();
    List<T> toList();
    int lengthBytes();
    byte[] bytes() throws IOException;

    static <T> Vector<T> parse(ByteBuffer buffer, int lengthBytes,
            ContentParser<T> parser) {

        List<T> objects = new ArrayList<>();
        buffer = ByteBuffer.wrap(getVectorBytes(buffer, lengthBytes));
        while (buffer.remaining() > 0) {
            objects.add(parser.parse(buffer));
        }

        return new VectorImpl<T>(lengthBytes, objects);
    }
    
    static Vector<Byte> parseOpaqueVector(ByteBuffer buffer, int lengthBytes) {
        return parse(buffer, lengthBytes, b -> b.get());
    }
    
    static byte[] getVectorBytes(ByteBuffer buffer, int lengthBytes) {
        byte[] lengthEncoding = new byte[lengthBytes];
        buffer.get(lengthEncoding);
        int length = Converter.bytes2int(lengthEncoding);
        
        byte[] bytes = new byte[length];
        buffer.get(bytes);

        return bytes;
    }

    static <T> Vector<T> wrap(int lengthBytes, List<T> objects) {
        List<T> objectList = new ArrayList<>();
        objectList.addAll(objects);
        return new VectorImpl<>(lengthBytes, objectList);
    }

    static <T> Vector<T> wrap(int lengthBytes, T... objects) {
        List<T> objectList = new ArrayList<>();
        objectList.addAll(Arrays.asList(objects));
        return wrap(lengthBytes, objectList);
    }

    static Vector<Byte> wrap(int lengthBytes, byte[] bytes) {
        return new VectorImpl<>(lengthBytes, Utils.toList(bytes));
    }

    static long maxEncodingLength(int lengthBytes) {
        return (long) (Math.pow(256, lengthBytes) - 1);
    }

    static <T> List<byte[]> encodingsList(List<T> objects) throws IOException {
        List<byte[]> encodings = new ArrayList<>();
        for (T value : objects) {
            byte[] encoding;
            if (value instanceof Struct) {
                encoding = ((Struct) value).encoding();
            } else if (value instanceof Byte) {
                encoding = new byte[] { (Byte) value };
            } else {
                throw new IllegalArgumentException();
            }

            encodings.add(encoding);
        }

        return encodings;
    }

    static int encodingsLength(List<byte[]> encodings) {
        int length = 0;
        for (byte[] encoding : encodings) {
            length += encoding.length;
        }

        return length;
    }

    static boolean equals(Vector first, Vector second) throws IOException {
        if (first == second) {
            return true;
        }

        if (first == null || second == null) {
            return false;
        }

        if (first.encodingLength() != second.encodingLength()) {
            return false;
        }

        return Arrays.equals(first.encoding(), second.encoding());
    }

}
