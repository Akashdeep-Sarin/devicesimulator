package com.akash.devicesimulator;

import java.util.Date;

import com.akash.devicesimulator.pojo.Thing;
import com.akash.devicesimulator.util.Utility;
import com.akash.devicesimulator.util.Utility.KeyStorePasswordPair;
import com.amazonaws.services.iot.client.AWSIotDevice;
import com.amazonaws.services.iot.client.AWSIotException;
import com.amazonaws.services.iot.client.AWSIotMqttClient;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

public class DeviceManager implements Runnable {

    private static AWSIotMqttClient awsIotClient;

    private String thingName;
    private Thing thing = new Thing();
    private ObjectMapper objectMapper = new ObjectMapper();

    DeviceManager(String thingName) {
        super();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.thingName = thingName;
    }

    private void initClient() {
        String clientEndpoint = Utility.getConfig("clientEndpoint");
        String clientId = this.thingName;
        String certificateFile = Utility.getConfig("certificateFile");
        String privateKeyFile = Utility.getConfig("privateKeyFile");

        if (awsIotClient == null && certificateFile != null && privateKeyFile != null) {
            KeyStorePasswordPair pair = Utility.getKeyStorePasswordPair(certificateFile, privateKeyFile, null);
            awsIotClient = new AWSIotMqttClient(clientEndpoint, clientId, pair.keyStore, pair.keyPassword);
        }

        if (awsIotClient == null) {
            throw new IllegalArgumentException("Failed to construct client due to missing certificate or credentials.");
        }
    }

    public void run() {
        initClient();

        AWSIotDevice device = new AWSIotDevice(thingName);

        try {
            awsIotClient.attach(device);
            awsIotClient.connect();

        } catch (AWSIotException e) {
            e.printStackTrace();
        }

        while (true) {
            postData(device);
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    void postData(AWSIotDevice device) {
        thing.setTemperture(Math.random() * 100F);

        String jsonState = null;
        try {
            jsonState = objectMapper.writeValueAsString(thing);
            thing.setTemperture(Math.random() * 100F);
            device.update(jsonState);
            System.out.println(new Date().toString() + ": " + jsonState);
        } catch (AWSIotException | JsonProcessingException e) {
            System.out.println("Update failed for " + jsonState);
        }
    }
}
