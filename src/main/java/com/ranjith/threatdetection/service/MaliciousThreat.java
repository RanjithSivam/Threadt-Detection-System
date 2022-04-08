package com.ranjith.threatdetection.service;

import java.util.Optional;

import com.ranjith.threatdetection.repository.RocksRepository;

public class MaliciousThreat {
	
	private RocksRepository rocksRepository;
	public static MaliciousThreat maliciousThreat;
	
	private MaliciousThreat(){
		rocksRepository = RocksRepository.getRocksRepository();
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
