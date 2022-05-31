package com.ranjith.threatdetection.model;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

public class ThreatSourceData implements Serializable{
	private static final long serialVersionUID = 1L;
	private Integer reputation;
	private JSONArray category;
	
	public ThreatSourceData() {
		super();
	}
	
	public ThreatSourceData(Integer reputation, JSONArray category) {
		super();
		this.reputation = reputation;
		this.category = category;
	}
	
	public Integer getReputation() {
		return reputation;
	}
	public void setReputation(Integer reputation) {
		this.reputation = reputation;
	}
	public JSONArray getCategory() {
		return category;
	}
	public void setCategory(JSONArray category) {
		this.category = category;
	}

	@Override
	public String toString() {
		return "ThreatSourceData [reputation=" + reputation + ", category=" + category + "]";
	}
	
}
