package com.ranjith.threatdetection.repository;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Optional;

import org.rocksdb.Options;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;

public class RocksRepository implements RocksRepositoryInterface<String, String> {
	
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
	        System.out.println("RocksDB initialized");
	      } catch(IOException | RocksDBException e) {
	        System.out.println("Error initializng RocksDB."+e.getMessage());
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
			System.out.println("Error saving entry.");
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
		      System.out.println(
		        "Error retrieving the entry with key: {}, cause: {}, message: {}"
		      );
		    }
		return Optional.ofNullable(value);
	}

	@Override
	public boolean delete(String key) {
		try {
		      db.delete(key.getBytes());
		    } catch (RocksDBException e) {
		      System.out.println("Error deleting entry, cause: '{}', message: '{}'");
		      return false;
		    }
		    return true;
	}
}
