package com.ranjith.threatdetection.repository;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Optional;
import java.util.logging.Logger;

import org.rocksdb.Options;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;


public class RocksRepository implements RepositoryInterface<String, String> {
	
	Logger log = Logger.getLogger(RocksRepository.class.getName());
	
	private final static String FILE_NAME = "threat-detection";
	 private File baseDir;
	  private RocksDB db;
	  private static RocksRepository rocksRepository;
	  
	private RocksRepository() throws IOException, RocksDBException{
		RocksDB.loadLibrary();
	    final Options options = new Options();
	    options.setCreateIfMissing(true);
	    baseDir = new File("/tmp/rocks", FILE_NAME);
	    Files.createDirectories(baseDir.getParentFile().toPath());
        Files.createDirectories(baseDir.getAbsoluteFile().toPath());
        db = RocksDB.open(options, baseDir.getAbsolutePath());
        
        log.info("RocksDB initialized");
	    
    	Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
			@Override
			public void run() {
				db.close();
			}
    	}));
	}
	
	
	public static RocksRepository getRocksRepository() throws IOException, RocksDBException {
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
			log.severe("Error Saving in RocksDB. Exception:" + e.getCause() +", message: "+ e.getMessage());
			return false;
		}catch(NullPointerException e) {
			log.severe("Rocks db is not initialized.");
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
		    	log.severe("Error retreving key from RocksDB. Exception:" + e.getCause() +", message: "+ e.getMessage());
		    }catch(NullPointerException e) {
				log.severe("Rocks db is not initialized.");
			}
		return Optional.ofNullable(value);
	}

	@Override
	public boolean delete(String key) {
		try {
		      db.delete(key.getBytes());
		    } catch (RocksDBException e) {
		    	log.severe("Error deleting from RocksDB. Exception:" + e.getCause() +", message: "+ e.getMessage());
		      return false;
		    }catch(NullPointerException e) {
				log.severe("Rocks db is not initialized.");
				return false;
			}
		    return true;
	}
}
