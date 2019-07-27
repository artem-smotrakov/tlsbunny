package com.gypsyengineer.tlsbunny.tls;

import java.io.IOException;

/**
 * TLS structure.
 */
public interface Struct {

    /**
     * Returns a length of encoding.
     */
    int encodingLength();

    /**
     * Encodes the object to a byte array.
     */
    byte[] encoding() throws IOException;

    /**
     * Returns a copy of the object.
     */
    Struct copy();

    /**
     * Returns true if the object contains of elements.
     */
    default boolean composite() {
        return false;
    }

    /**
     * Returns a number of elements in the object.
     */
    default int total() {
        return 0;
    }

    /**
     * Returns an element by the specified index.
     */
    default Struct element(int index) {
        throw new UnsupportedOperationException("no elements for you!");
    }

    /**
     * Sets an element by the specified index.
     */
    default void element(int index, Struct element) {
        throw new UnsupportedOperationException("no setting elements for you!");
    }

}
