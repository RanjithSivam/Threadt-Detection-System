package com.ranjith.threatdetection.service;

import java.util.Optional;

import com.ranjith.threatdetection.repository.MapDBRepository;
import com.ranjith.threatdetection.repository.RepositoryInterface;

public class MaliciousThreat {
	
	private RepositoryInterface<String, String> repository;
	public static MaliciousThreat maliciousThreat;
	
	private MaliciousThreat(){
		//			repository = RocksRepository.getRocksRepository();
		repository = MapDBRepository.getMapDBRepository();
	}
	
	public static MaliciousThreat getMaliciousThreat() {
		if(maliciousThreat==null) {
			maliciousThreat = new MaliciousThreat();
		}
		
		return maliciousThreat;
	}
	
	public Optional<String> isMalicious(String ip) {
		return repository.find(ip);
	}
}
