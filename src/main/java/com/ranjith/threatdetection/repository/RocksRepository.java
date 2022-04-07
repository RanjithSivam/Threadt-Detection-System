package com.ranjith.threatdetection.repository;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Optional;

import org.rocksdb.Options;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ranjith.threatdetection.service.ThreatFetch;



public class RocksRepository implements RocksRepositoryInterface<String, String> {
	
	Logger log = LoggerFactory.getLogger(RocksRepository.class);
	
	private final static String FILE_NAME = "threat-detection";
	 private File baseDir;
	  private RocksDB db;
	  private static RocksRepository rocksRepository;
	  
	private RocksRepository(){
		RocksDB.loadLibrary();
	    final Options options = new Options();
	    options.setCreateIfMissing(true);
	    baseDir = new File("/tmp/rocks", FILE_NAME);
	    
	    try {
	        Files.createDirectories(baseDir.getParentFile().toPath());
	        Files.createDirectories(baseDir.getAbsoluteFile().toPath());
	        db = RocksDB.open(options, baseDir.getAbsolutePath());
	        
	        log.info("RocksDB initialized");
	      } catch(IOException | RocksDBException e) {
	    	  log.error("Error initializng RocksDB. Exception: '{}', message: '{}'", e.getCause(), e.getMessage(), e);
	      }
	 
	}
	
	public static RocksRepository getRocksRepository() {
		if(rocksRepository==null) {
			rocksRepository = new RocksRepository();
		}
		
		return rocksRepository;
	}

	@Override
	public boolean save(String key, String value) {
		try {
		      db.put(key.getBytes(), value.getBytes());
		}catch(RocksDBException e) {
			log.error("Error saving entry. Cause: '{}', message: '{}'", e.getCause(), e.getMessage());
			return false;
		}
		return true;
	}

	@Override
	public Optional<String> find(String key) {
		String value = null;
		
		try {
		      byte[] bytes = db.get(key.getBytes());
		      if (bytes != null) value = new String(bytes);
		    } catch (RocksDBException e) {
		    	log.error(
		    	        "Error retrieving the entry with key: {}, cause: {}, message: {}", 
		    	        key, 
		    	        e.getCause(), 
		    	        e.getMessage()
		    	      );
		    }
		return Optional.ofNullable(value);
	}

	@Override
	public boolean delete(String key) {
		try {
		      db.delete(key.getBytes());
		    } catch (RocksDBException e) {
		    	log.error("Error deleting entry, cause: '{}', message: '{}'", e.getCause(), e.getMessage());
		      return false;
		    }
		    return true;
	}
}
