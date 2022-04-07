package com.ranjith.threatdetection.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.Scanner;

import org.apache.commons.io.input.ReversedLinesFileReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SearchLogs {
	
	Logger log = LoggerFactory.getLogger(SearchLogs.class);
	
	private FileSystem fs;
	private WatchService ws;
	private Path directory;
	private final String LOG_PATH = "/var/log";
	private MaliciousThreat maliciousThreat;
	private String lastReadLine;
	
	public SearchLogs() throws IOException{
		fs  = FileSystems.getDefault();
		ws = fs.newWatchService();
		directory = fs.getPath(LOG_PATH).toAbsolutePath();
		maliciousThreat = MaliciousThreat.getMaliciousThreat();
		log.info("Monitoring firewall logs....");
	}
	
	public void watchForThreats() {
		WatchKey watchKey;
		try {
			watchKey = directory.register(ws,StandardWatchEventKinds.ENTRY_MODIFY);
			while(true) {
				for(WatchEvent<?> event : watchKey.pollEvents()) {
		            final Path changed = (Path) event.context();
		            if (changed.endsWith("ufw.log")) {
		                ReversedLinesFileReader fileReader = new ReversedLinesFileReader(new File(LOG_PATH+"/ufw.log"));
		                String currentLog;
		                String currentLastReadLine = null;
		                boolean first = true;
		                do {
		                	currentLog = fileReader.readLine();
		                	if(currentLog!=null) {
		                		if(lastReadLine!=null && lastReadLine.equals(currentLog)) {
			                		break;
			                	}
			                	String timeString = currentLog.substring(0,currentLog.indexOf(System.getProperty("user.name")));
			                	String source = currentLog.substring(currentLog.indexOf("SRC=")+4,currentLog.indexOf("DST")).trim();
			                	String destination = currentLog.substring(currentLog.indexOf("DST=")+4,currentLog.indexOf("LEN")).trim();
			                	if(maliciousThreat.isMalicious(source) || maliciousThreat.isMalicious(destination)) {
			                		log.warn("The followinf connection is malicious. source:{}, destination:{}, time:{}",source,destination,timeString);
			                	}
			                	if(first) {
			                		currentLastReadLine = currentLog;
			                		first = false;
			                	}
		                	}
		                }while(currentLog!=null);
		                
		                lastReadLine = currentLastReadLine;
		                fileReader.close();
		            }
				}
			}
		} catch (IOException e) {
			log.error(e.getMessage());
		}
	}
	
}
