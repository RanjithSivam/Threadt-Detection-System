package com.ranjith.threatdetection.service;

import java.io.IOException;
import java.util.Optional;

import org.rocksdb.RocksDBException;

import com.ranjith.threatdetection.repository.RocksRepository;

public class MaliciousThreat {
	
	private RocksRepository rocksRepository;
	public static MaliciousThreat maliciousThreat;
	
	private MaliciousThreat(){
		try {
			rocksRepository = RocksRepository.getRocksRepository();
		} catch (IOException | RocksDBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static MaliciousThreat getMaliciousThreat() {
		if(maliciousThreat==null) {
			maliciousThreat = new MaliciousThreat();
		}
		
		return maliciousThreat;
	}
	
	public Optional<String> isMalicious(String ip) {
		return rocksRepository.find(ip);
	}
}
