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

public class SearchLogs {
	
	private FileSystem fs;
	private WatchService ws;
	private Path directory;
	private final String LOG_PATH = "/var/log";
	private MaliciousThreat maliciousThreat;
	
	public SearchLogs() throws IOException{
		fs  = FileSystems.getDefault();
		ws = fs.newWatchService();
		directory = fs.getPath(LOG_PATH).toAbsolutePath();
		maliciousThreat = new MaliciousThreat();
	}
	
	public void watchForThreats() {
		WatchKey watchKey;
		try {
			watchKey = directory.register(ws,StandardWatchEventKinds.ENTRY_MODIFY);
			while(true) {
				for(WatchEvent<?> event : watchKey.pollEvents()) {
		            final Path changed = (Path) event.context();
		            if (changed.endsWith("ufw.log")) {
		                Scanner sc = new Scanner(new File(LOG_PATH+"/ufw.log"));
		                while(sc.hasNextLine()) {
		                	String log = sc.nextLine();
		                	String timeString = log.substring(0,log.indexOf(System.getProperty("user.name")));
		                	String source = log.substring(log.indexOf("SRC=")+4,log.indexOf("DST")).trim();
		                	String destination = log.substring(log.indexOf("DST=")+4,log.indexOf("LEN")).trim();
		                	if(maliciousThreat.isMalicious(source) || maliciousThreat.isMalicious(destination)) {
		                		System.out.println("malicious");
		                	}
		                }
		            }
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
