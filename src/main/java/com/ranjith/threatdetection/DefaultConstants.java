package com.ranjith.threatdetection;

public class DefaultConstants {
	private static String FIREWALL_LOG = "/var/log";
	private static String THREAT_LOG = "/home/ranjith/Desktop";
	private static long FETCHING_TIMING = 3600000*24;
	private static String THREAT_LOG_NAME = "ufw.log";
	
	public static String getFIREWALL_LOG() {
		return FIREWALL_LOG;
	}
	public static void setFIREWALL_LOG(String fIREWALL_LOG) {
		FIREWALL_LOG = fIREWALL_LOG;
	}
	public static String getTHREAT_LOG() {
		return THREAT_LOG;
	}
	public static void setTHREAT_LOG(String tHREAT_LOG) {
		THREAT_LOG = tHREAT_LOG;
	}
	public static long getFETCHING_TIMING() {
		return FETCHING_TIMING;
	}
	public static void setFETCHING_TIMING(long fETCHING_TIMING) {
		FETCHING_TIMING = fETCHING_TIMING;
	}
	
	public static String getTHREAT_LOG_NAME() {
		return THREAT_LOG_NAME;
	}
	public static void setTHREAT_LOG_NAME(String tHREAT_LOG_NAME) {
		THREAT_LOG_NAME = tHREAT_LOG_NAME;
	}
	public static long hoursToMilliSeconds(int hours) {
		return 3600000*hours;
	}
	
	public static long milliSecondsToHours(long milli) {
		return milli/3600000;
	}
}
