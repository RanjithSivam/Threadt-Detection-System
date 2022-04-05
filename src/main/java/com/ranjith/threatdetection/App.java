package com.ranjith.threatdetection;

import com.ranjith.threatdetection.model.Source;
import com.ranjith.threatdetection.model.Sources;
import com.ranjith.threatdetection.service.ThreatFetch;


public class App 
{
    public static void main( String[] args )
    {
    	Sources sources = new Sources();
    	sources.setList("http://hailataxii.com/taxii-data", "guest", "guest", "guest.phishtank_com");
    	
    	
    	for(Source source:sources.getList()) {
    		ThreatFetch fetch = new ThreatFetch(source);
    		fetch.pollRequest();
    	}
    }
}
