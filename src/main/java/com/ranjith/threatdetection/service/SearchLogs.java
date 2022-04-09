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
import java.util.Optional;
import java.util.logging.FileHandler;
import java.util.logging.Logger;

import org.apache.commons.io.input.ReversedLinesFileReader;

public class SearchLogs extends Thread{
	
	Logger fileLog = Logger.getLogger(SearchLogs.class.getName());
	Logger log = Logger.getLogger(SearchLogs.class.getName());
	
	private FileSystem fs;
	private WatchService ws;
	private Path directory;
	private final String FIREWALL_LOG_PATH = "/var/log";
	private final String THREAT_LOG = "/home/ranjith/Desktop/threat.log";
	private MaliciousThreat maliciousThreat;
	private String lastReadLine;
	
	public SearchLogs() throws IOException{
		fs  = FileSystems.getDefault();
		ws = fs.newWatchService();
		directory = fs.getPath(FIREWALL_LOG_PATH).toAbsolutePath();
		maliciousThreat = MaliciousThreat.getMaliciousThreat();
		log.info("Monitoring firewall logs....");
		try {
			FileHandler fileHandler = new FileHandler(THREAT_LOG, true);
			fileLog.addHandler(fileHandler);
		} catch (SecurityException | IOException e) {
			log.severe(e.getMessage());
		}
	}
	
	public void watchForThreats() {
		WatchKey watchKey;
		try {
			watchKey = directory.register(ws,StandardWatchEventKinds.ENTRY_MODIFY);
			while(true) {
				for(WatchEvent<?> event : watchKey.pollEvents()) {
		            final Path changed = (Path) event.context();
		            if (changed.endsWith("ufw.log")) {
		                try(ReversedLinesFileReader fileReader = new ReversedLinesFileReader(new File(FIREWALL_LOG_PATH+"/ufw.log"))) {
			                String currentLog;
			                String currentLastReadLine = null;
			                boolean first = true;
			                
			                while((currentLog = fileReader.readLine())!=null) {
			                	if(lastReadLine!=null && lastReadLine.equals(currentLog)) {
			                		break;
			                	}
			                	String timeString = currentLog.substring(0,currentLog.indexOf(System.getProperty("user.name")));
			                	String source = currentLog.substring(currentLog.indexOf("SRC=")+4,currentLog.indexOf("DST")).trim();
			                	String destination = currentLog.substring(currentLog.indexOf("DST=")+4,currentLog.indexOf("LEN")).trim();
			                	Optional<String> isThreat = maliciousThreat.isMalicious(destination);
			                	if(isThreat.isPresent()) {
			                		fileLog.warning("The following connection is malicious. source: "+source+", destination:"+ destination +", time: "+timeString +", info: "+isThreat.get());
			                	}
			                	if(first) {
			                		currentLastReadLine = currentLog;
			                		first = false;
			                	}
			                }
			                
			                lastReadLine = currentLastReadLine;
		                }
		            }
				}
			}
		} catch (IOException e) {
			log.severe(e.getMessage());
		}
	}
	
	@Override
    public void run() {
		watchForThreats();
    }
}
