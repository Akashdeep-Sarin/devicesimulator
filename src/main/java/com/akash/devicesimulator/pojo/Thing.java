package com.akash.devicesimulator.pojo;

import java.text.SimpleDateFormat;
import java.util.Date;

public class Thing {

	private static SimpleDateFormat format = new SimpleDateFormat("hh-mm-ss dd-MM-yyyy");

	public State state = new State();

	public static class State {
		public Temperature reported = new Temperature();
	}

	public static class Temperature {
		public double value;
		public String timeString;
	}

	public void setTemperture(double temperature) {
		this.state.reported.timeString = format.format(new Date());
		this.state.reported.value = temperature;
	}

}
