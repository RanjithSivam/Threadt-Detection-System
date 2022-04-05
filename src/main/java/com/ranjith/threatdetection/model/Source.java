package com.ranjith.threatdetection.model;

public class Source {
	private String url;
	private String username;
	private String password;
	private String feed;
	
	public Source(String url, String username, String password,String feed) {
		super();
		this.url = url;
		this.username = username;
		this.password = password;
		this.feed = feed;
	}
	
	public String getUrl() {
		return url;
	}
	public void setUrl(String url) {
		this.url = url;
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

	public String getFeed() {
		return feed;
	}

	public void setFeed(String feed) {
		this.feed = feed;
	}
	
}
