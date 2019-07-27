package com.gypsyengineer.tlsbunny.utils;

import com.gypsyengineer.tlsbunny.output.*;
import com.gypsyengineer.tlsbunny.tls13.client.Client;
import com.gypsyengineer.tlsbunny.tls13.server.Server;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import static com.gypsyengineer.tlsbunny.output.Level.achtung;
import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class SyncImpl implements Sync {

    public enum VerboseLevel {
        fuzzing, limited, all
    }

    private static final int n = 100;

    private static VerboseLevel verboseLevel = VerboseLevel.valueOf(
            System.getProperty("tlsbunny.sync.output", VerboseLevel.all.name()));

    private static final boolean globalPrintToFile =
            Boolean.valueOf(System.getProperty(
                    "tlsbunny.output.to.file", "false"));

    private Client client;
    private Server server;
    private StandardOutput standardOutput;
    private Output fileOutput;
    private int clientIndex;
    private int serverIndex;
    private String logPrefix = "";
    private boolean initialized = false;
    private long tests = 0;
    private long testStarted;
    private long testsDuration = 0;

    private boolean printToFile = globalPrintToFile;
    private String logDirectory;

    @Override
    public Sync logs(String path) {
        logDirectory = path;
        return this;
    }

    @Override
    public Sync printToFile() {
        printToFile = true;
        return this;
    }

    @Override
    public Sync logPrefix(String logPrefix) {
        this.logPrefix = logPrefix;
        return this;
    }

    @Override
    public SyncImpl set(Client client) {
        this.client = client;
        initialized = false;
        return this;
    }

    @Override
    public SyncImpl set(Server server) {
        this.server = server;
        initialized = false;
        return this;
    }

    @Override
    public SyncImpl init() {
        Objects.requireNonNull(client, "client can't be null!");
        Objects.requireNonNull(server, "server can't be null!");

        standardOutput = Output.standard();
        standardOutput.prefix("");

        if (printToFile) {
            if (logDirectory == null) {
                logDirectory = String.format("logs/%s",
                        new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss").format(new Date()));
            }

            File file = new File(logDirectory);
            if (!file.exists()) {
                boolean success = file.mkdirs();
                if (!success) {
                    throw whatTheHell("could not create directories");
                }
            }

            String path = String.format("%s/%s_%d.log",
                    logDirectory, logPrefix, System.currentTimeMillis());
            fileOutput = Output.file(path);
            fileOutput.prefix("");
        }

        try (Output output = Output.local()) {
            output.info("[sync] init");

            output.info("[sync] client output");
            List<Line> clientLines = client.output().lines();
            for (; clientIndex < clientLines.size(); clientIndex++) {
                output.add(clientLines.get(clientIndex));
            }

            output.info("[sync] server output");
            List<Line> serverLines = server.output().lines();
            for (; serverIndex < serverLines.size(); serverIndex++) {
                output.add(serverLines.get(serverIndex));
            }

            standardOutput.add(output);
            standardOutput.flush();
        }

        clientIndex = client.output().lines().size();
        serverIndex = server.output().lines().size();

        initialized = true;
        return this;
    }

    @Override
    public SyncImpl start() {
        checkInitialized();
        testStarted = System.nanoTime();
        return this;
    }

    @Override
    public SyncImpl end() {
        checkInitialized();

        long time = System.nanoTime() - testStarted;
        testsDuration += time;

        try (Output output = Output.local()) {
            output.info("[sync] client output");
            List<Line> clientLines = client.output().lines();
            for (; clientIndex < clientLines.size(); clientIndex++) {
                output.add(clientLines.get(clientIndex));
            }

            output.info("[sync] server output");
            List<Line> serverLines = server.output().lines();
            boolean found = false;
            for (; serverIndex < serverLines.size(); serverIndex++) {
                Line line = serverLines.get(serverIndex);
                if (line.value().contains("ERROR: AddressSanitizer:")) {
                    found = true;
                }
                output.add(line);
            }

            output.info("[sync] end");
            output.flush();

            if (found) {
                output.achtung("oops!");
                output.achtung("Looks like AddressSanitizer found something");

                standardOutput.add(output, achtung);

                if (printToFile) {
                    fileOutput.add(output, achtung);
                    fileOutput.flush();

                    String path = String.format("%s/oops_%s_%d.log",
                            logDirectory, logPrefix, System.currentTimeMillis());
                    try (Output oopsOutput = Output.file(path)) {
                        oopsOutput.add(output, achtung);
                    }
                }
            } else {
                if (++tests % n == 0) {
                    long speed = n * 60000000000L / testsDuration;
                    standardOutput.important("%d tests done, %d tests / minute",
                            tests, speed);
                    testsDuration = 0;
                }

                if (verboseLevel == VerboseLevel.all) {
                    standardOutput.add(output);
                }

                if (printToFile) {
                    fileOutput.add(output);
                    fileOutput.flush();
                    fileOutput.clear();
                }
            }

            standardOutput.flush();
            standardOutput.clear();
        }

        client.output().clear();
        server.output().clear();

        clientIndex = 0;
        serverIndex = 0;

        return this;
    }

    @Override
    public Output output() {
        return standardOutput;
    }

    private void checkInitialized() {
        if (!initialized) {
            throw whatTheHell("Sync is not initialized!");
        }
    }

    @Override
    public void close() {
        standardOutput.close();
        if (printToFile) {
            fileOutput.close();
        }
    }

}
