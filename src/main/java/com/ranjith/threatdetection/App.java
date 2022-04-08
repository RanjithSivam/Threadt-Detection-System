package com.ranjith.threatdetection;

import java.io.IOException;

import org.rocksdb.RocksDBException;

import com.ranjith.threatdetection.model.Source;
import com.ranjith.threatdetection.model.Sources;
import com.ranjith.threatdetection.repository.RocksRepository;
import com.ranjith.threatdetection.service.SearchLogs;
import com.ranjith.threatdetection.service.ThreatFetch;


public class App
{
    public static void main( String[] args )
    {
//    	JFrame frame = new JFrame();
//    	frame.setSize(100,100);
//    	frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//    	frame.setVisible(true);
//    	
//    	JPanel panel = new JPanel();
//    	frame.add(panel);
//    	
//    	panel.setLayout(null);
//    	
//    	JButton start = new JButton("Start");
//    	start.setBounds(10,80,80,25);
//    	start.addActionListener(new App());
//    	panel.add(start);
    	
    	try {
			startService();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public static void startService() throws IOException {
    	Sources sources = new Sources();
    	sources.setList("http://hailataxii.com/taxii-data", "guest","guest","guest.phishtank_com");
    	sources.setList("https://otx.alienvault.com/taxii", "441273a7ae6eb344d9fa728071edd89c6b005f1f3ca49e8cf333ec3e40a1648f", "", "user_AlienVault");
    	
    	try {
    		RocksRepository.getRocksRepository();
    		for(Source source:sources.getList()) {
        		ThreatFetch fetch = new ThreatFetch(source);
        		fetch.start();
        	}
        	
        	SearchLogs searchLogs = new SearchLogs();
        	searchLogs.start();
    	}catch(IOException | RocksDBException e) {
	    	  System.out.println("Error initializng RocksDB. Exception:" + e.getCause() +", message: "+ e.getMessage());
	      }
    
    }

//	@Override
//	public void actionPerformed(ActionEvent e) {
//		System.out.println("clicked");
//		try {
//			startService();
//		} catch (IOException e1) {
//			// TODO Auto-generated catch block
//			e1.printStackTrace();
//		}
//	}
}
