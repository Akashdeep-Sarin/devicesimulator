package com.akash.devicesimulator;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import static com.akash.devicesimulator.util.Constants.*;

@SpringBootApplication
public class Simulator {
	static String deviceName;
	static Integer offset;
	static Double flickerFactor;
	static Double curveSpeed;
	static Double iterationCount = 1D;
	
	public static void main(String[] args) {
		
		System.out.println("Starting Simulator...!!! ");

		for(int i=0; i<args.length; i++) {
			if (args[i].startsWith(DEVICENAME)) {
				Simulator.deviceName = args[i].substring(DEVICENAME.length());
			} 
		}
		
		System.out.println("Device: "+ deviceName);
	
		Thread simulatorThread = new Thread(new DeviceManager(deviceName));
		simulatorThread.start();
	}
}
