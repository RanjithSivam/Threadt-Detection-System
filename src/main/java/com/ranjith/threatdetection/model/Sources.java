package com.ranjith.threatdetection.model;

import java.util.ArrayList;
import java.util.List;

public class Sources {
	
	private List<Source> list;

	public List<Source> getList() {
		return list;
	}
	
	public Sources() {
		list = new ArrayList();
	}

	public void setList(String url,String username,String password) {
		Source source = new Source(url,username,password);
		list.add(source);
	}
}
