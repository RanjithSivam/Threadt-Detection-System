package com.ranjith.threatdetection.service;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;

public class SearchLogs {
	
	private FileSystem fs;
	private WatchService ws;
	private Path directory;
	
	public SearchLogs() throws IOException{
		fs  = FileSystems.getDefault();
		ws = fs.newWatchService();
		directory = fs.getPath("/var/log").toAbsolutePath();
	}
	
	public void watchForThreats() {
		WatchKey watchKey;
		try {
			watchKey = directory.register(ws,StandardWatchEventKinds.ENTRY_MODIFY);
			while(true) {
				for(WatchEvent<?> event : watchKey.pollEvents()) {
		            final Path changed = (Path) event.context();
		            if (changed.endsWith("ufw.log")) {
		                System.out.println("My file has changed");
		            }
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
