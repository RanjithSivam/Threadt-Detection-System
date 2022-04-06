package com.ranjith.threatdetection;

import java.io.IOException;

import com.ranjith.threatdetection.model.Sources;
import com.ranjith.threatdetection.service.SearchLogs;


public class App 
{
    public static void main( String[] args ) throws IOException
    {
    	Sources sources = new Sources();
    	sources.setList("http://hailataxii.com/taxii-data", "guest", "guest", "guest.phishtank_com");
    	sources.setList("https://otx.alienvault.com/taxii/poll", "441273a7ae6eb344d9fa728071edd89c6b005f1f3ca49e8cf333ec3e40a1648f", "", "user_AlienVault");
    	
//    	for(Source source:sources.getList()) {
//    		ThreatFetch fetch = new ThreatFetch(source);
//    		fetch.pollRequest();
//    	}
    	
    	SearchLogs searchLogs = new SearchLogs();
    	searchLogs.watchForThreats();
    	
    }
}