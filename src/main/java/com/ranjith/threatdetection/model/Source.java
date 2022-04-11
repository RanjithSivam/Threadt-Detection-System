package com.ranjith.threatdetection.model;

public class Source {
	private String dicoverUrl;
	private String username;
	private String password;
	
	public Source(String dicoverUrl, String username, String password) {
		super();
		this.dicoverUrl = dicoverUrl;
		this.username = username;
		this.password = password;
	}
	
	public String getDicoverUrl() {
		return dicoverUrl;
	}
	public void setDicoverUrl(String dicoverUrl) {
		this.dicoverUrl = dicoverUrl;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	
}
