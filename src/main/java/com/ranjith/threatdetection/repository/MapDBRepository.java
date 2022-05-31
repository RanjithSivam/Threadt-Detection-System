package com.ranjith.threatdetection.repository;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.XML;
import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.HTreeMap;
import org.mapdb.Serializer;

import com.ranjith.threatdetection.model.ThreatSourceData;
import com.ranjith.threatdetection.util.ThreatSourceDataSerializer;

public class MapDBRepository implements RepositoryInterface<String, String> {
	
	private final static String FILE_NAME = "threat-detection.db";
	private File baseDir;
	private DB db;
	private HTreeMap<Long, ThreatSourceData> hash;
	private static MapDBRepository mapDBRepository;
	
	private MapDBRepository() throws IOException {
		baseDir = new File("/tmp/maps", FILE_NAME);
		db = DBMaker.fileDB(baseDir).closeOnJvmShutdown().make();
		hash = db.hashMap("map",Serializer.LONG,new ThreatSourceDataSerializer()).createOrOpen();
	}
	
	public static MapDBRepository getMapDBRepository() {
		if(mapDBRepository==null)
			try {
				mapDBRepository = new MapDBRepository();
			} catch (IOException e) {
				e.printStackTrace();
			}
		return mapDBRepository;
	}

	@Override
	public boolean save(String key, String value) {
		System.out.println(value);
		if(!hash.containsKey(ipToLong(key))) {
			JSONArray arr = new JSONArray();
//			arr.put(XML.toJSONObject(value));
			arr.put(value);
			ThreatSourceData source = new ThreatSourceData();
			source.setCategory(arr);
			source.setReputation((int)(Math.random()*100.0));
			hash.put(ipToLong(key), source);
		}else {
			ThreatSourceData source = hash.get(ipToLong(key));
			JSONArray arr = source.getCategory();
//			arr.put(XML.toJSONObject(value));
			arr.put(value);
			source.setCategory(arr);
			hash.put(ipToLong(key), source);
		}
		return true;
	}

	@Override
	public Optional<String> find(String key) {
		return Optional.of(hash.get(ipToLong(key)).toString());
	}

	@Override
	public boolean delete(String key) {
		if(hash.containsKey(ipToLong(key))) hash.remove(ipToLong(key));
		return true;
	}
	
	@Override
	public void print() {
		hash.forEach((a,b) -> System.out.println("Key: "+a+"---- Value: "+b));
	}
	
	private Long ipToLong(String ip) {
		long convertedIp = 0;
		int val = 3;
		for(String block:ip.split("\\.")) {
			convertedIp += Integer.parseInt(block)*Math.pow(256, val--);
		}
		
		return convertedIp;
	}

}
