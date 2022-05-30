package com.ranjith.threatdetection.repository;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Optional;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.HTreeMap;
import org.mapdb.Serializer;

public class MapDBRepository implements RepositoryInterface<String, String> {
	
	private final static String FILE_NAME = "threat-detection.db";
	private File baseDir;
	private DB db;
	private HTreeMap<String, String> hash;
	private static MapDBRepository mapDBRepository;
	
	private MapDBRepository() throws IOException {
		baseDir = new File("/tmp/maps", FILE_NAME);
		db = DBMaker.fileDB(baseDir).closeOnJvmShutdown().make();
		hash = db.hashMap("map",Serializer.STRING,Serializer.STRING).createOrOpen();
	}
	
	public static MapDBRepository getMapDBRepository() {
		if(mapDBRepository==null)
			try {
				mapDBRepository = new MapDBRepository();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		return mapDBRepository;
	}

	@Override
	public boolean save(String key, String value) {
		if(!hash.containsKey(value)) hash.put(key, value);
		return true;
	}

	@Override
	public Optional<String> find(String key) {
		return Optional.of(hash.get(key));
	}

	@Override
	public boolean delete(String key) {
		if(hash.containsKey(key)) hash.remove(key);
		return true;
	}

}
