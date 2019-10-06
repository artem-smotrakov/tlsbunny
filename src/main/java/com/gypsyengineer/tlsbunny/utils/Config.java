package com.gypsyengineer.tlsbunny.utils;

import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.SystemConfiguration;
import org.apache.commons.configuration2.builder.fluent.Configurations;
import org.apache.commons.configuration2.ex.ConfigurationException;

import java.nio.file.Files;
import java.nio.file.Paths;

import static com.gypsyengineer.tlsbunny.utils.WhatTheHell.whatTheHell;

public class Config {

    private static final String configFileName = "tlsbunny.properties";

    public static final Configuration instance = init();

    private static Configuration init() {
        Configurations configurations = new Configurations();

        if (Files.exists(Paths.get(configFileName))) {
            try {
                return configurations.properties(configFileName);
            } catch (ConfigurationException e) {
                throw whatTheHell("could not load configuration", e);
            }
        }

        return new SystemConfiguration();
    }

}