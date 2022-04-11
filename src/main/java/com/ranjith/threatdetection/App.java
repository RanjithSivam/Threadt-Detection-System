package com.ranjith.threatdetection;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

import org.rocksdb.RocksDBException;

import com.ranjith.threatdetection.model.Source;
import com.ranjith.threatdetection.model.Sources;
import com.ranjith.threatdetection.repository.RocksRepository;
import com.ranjith.threatdetection.service.ThreatFetch;


public class App
{
    public static void main( String[] args )
    {
    	System.out.println("Welcome to Threat Detection Application");
    	
    	try(Scanner sc = new Scanner(System.in)){
    		while(true) {
        		System.out.println("Options available\n 1.Change fetching period\n 2.Change firewall log file monitoring\n 3.Change log file location\n 4.Change firewall log file to monitor\n 5.Start the application\n");
        		int option = sc.nextInt();
        		switch(option) {
        		case 1:
        			System.out.println("Default feed fetch timing: "+DefaultConstants.milliSecondsToHours(DefaultConstants.getFETCHING_TIMING())+" hours");
        			System.out.println("Enter time in hours to change: ");
        			int time = sc.nextInt();
        			DefaultConstants.setFETCHING_TIMING(DefaultConstants.hoursToMilliSeconds(time));
        			break;
        		case 2:
        			System.out.println("Default firewall log location: "+DefaultConstants.getFIREWALL_LOG());
        			System.out.println("Enter the firewall log directory: ");
        			String directory = sc.next();
        			Path path = Paths.get(directory);
        			if(Files.exists(path)) {
        				DefaultConstants.setFIREWALL_LOG(directory);
        			}
        			break;
        		case 3:
        			System.out.println("Default threat log location: "+DefaultConstants.getTHREAT_LOG());
        			System.out.println("Enter the threat log directory: ");
        			directory = sc.next();
        			path = Paths.get(directory);
        			if(Files.exists(path)) {
        				DefaultConstants.setTHREAT_LOG(directory);
        			}
        			break;
        		case 4:
        			System.out.println("Default firewall log name: "+DefaultConstants.getTHREAT_LOG_NAME());
        			System.out.println("Enter the firewall log name: ");
        			String name = sc.next();
        			DefaultConstants.setTHREAT_LOG_NAME(name);
        			break;
        		case 5:
        			startService();
        			return;
        		default:
        			continue;
        		}
        	}
    	}
    }
    
    public static void startService() {
    	Sources sources = new Sources();
    	sources.setList("http://hailataxii.com/taxii-data", "guest","guest");
//    	sources.setList("https://otx.alienvault.com/taxii/discovery", "441273a7ae6eb344d9fa728071edd89c6b005f1f3ca49e8cf333ec3e40a1648f", "");
    	
    	try {
    		RocksRepository.getRocksRepository();
    		for(Source source:sources.getList()) {
        		ThreatFetch fetch = new ThreatFetch(source);
        		fetch.start();
        	}
        	
//        	SearchLogs searchLogs = new SearchLogs();
//        	searchLogs.start();
    	}catch(IOException | RocksDBException e) {
	    	  System.out.println("Error initializng RocksDB. Exception:" + e.getCause() +", message: "+ e.getMessage());
	      }
    
    }
}
