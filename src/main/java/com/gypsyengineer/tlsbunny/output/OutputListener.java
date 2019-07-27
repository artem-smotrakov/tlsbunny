package com.gypsyengineer.tlsbunny.output;

public interface OutputListener {
    void receivedInfo(String... strings);
    void receivedImportant(String... strings);
    void receivedAchtung(String... strings);
}
