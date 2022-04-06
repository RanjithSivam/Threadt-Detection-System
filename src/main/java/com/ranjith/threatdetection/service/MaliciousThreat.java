package com.ranjith.threatdetection.service;

import com.ranjith.threatdetection.repository.RocksRepository;

public class MaliciousThreat {
	
	private RocksRepository rocksRepository;
	
	MaliciousThreat(){
		rocksRepository = RocksRepository.getRocksRepository();
	}
	
	public boolean isMalicious(String ip) {
		return rocksRepository.find(ip).isPresent();
	}
}
