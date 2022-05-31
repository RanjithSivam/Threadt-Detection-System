package com.ranjith.threatdetection.repository;

import java.util.Optional;

public interface RepositoryInterface<K,V> {
	boolean save(K key, V value);
	  Optional<V> find(K key);
	  boolean delete(K key);
	  void print();
}
