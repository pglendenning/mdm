/**
 * 
 */
package com.mdm.utils;

import java.util.HashMap;
import java.lang.ref.WeakReference;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;

/**
 * @author paul
 *
 */
public class ObjectCache<T> {
	
	private class CacheEntry {
		public WeakReference<CacheEntry> next;
		public WeakReference<CacheEntry> prev;
		public WeakReference<CacheEntry> curr;
		public T		object;
		public String	id;
		
		CacheEntry() {
			curr = next = prev = new WeakReference<CacheEntry>(this);
			object = null;
			id = null;
		}
		
		CacheEntry(T object, String id) {
			this.id = id;
			this.object = object;
			curr = prev = next = new WeakReference<CacheEntry>(this);
		}
		
		boolean isLinked() {
			return next != prev || next != curr;
		}
		
		// Remove from list. Safe even if the list is empty.
		CacheEntry unlink()
		{
			prev.get().next = next;
			next.get().prev = prev;
			prev = next = curr;
			return this;
		}
	}
	
    private Method cloneMethod; 
	private HashMap<String, CacheEntry> objectMap;
    private CacheEntry list;
    private int length;
    
	public ObjectCache() {
		cloneMethod = null;
		objectMap = new HashMap<String, CacheEntry>();
		list = new CacheEntry();
		length = 0;
		updateCloneType();
	}
	
    private CacheEntry pushFront(CacheEntry newItem) {
		assert !newItem.isLinked();
		newItem.next = list.next;
		newItem.prev = list.curr;
		list.next.get().prev = newItem.curr;
		list.next = newItem.curr;
		return newItem;
	}
    
    private CacheEntry pushBack(CacheEntry newItem) {
		assert !newItem.isLinked();
		newItem.prev = list.prev;
		newItem.next = list.curr;
		list.prev.get().next = newItem.curr;
		list.prev = newItem.curr;
		return newItem;
	}
	
    // Remove the least recently used entry
    private CacheEntry popBack() {
    	if (!list.isLinked())
    		return null;
    	CacheEntry entry = list.prev.get();
    	entry.unlink();
    	return entry;
    }
    
    private void updateCloneType() {
    	Method m = null;
    	try {
    		m = ((Class<?>) ((ParameterizedType) getClass()
    		        .getGenericSuperclass()).getActualTypeArguments()[0]).getMethod("clone");
    	} catch (Exception e) {
    		// ignore
    	}
    	cloneMethod = m;
    }
    
    /**
     * Get the length of the cache.
     * @return	The length.
     */
    public synchronized int getLength() {
    	return length;
    }
    
    /**
     * Test if the cache is empty.
     * @return	True if empty.
     */
    public synchronized boolean isEmpty() {
    	return !list.isLinked();
    }
    
    /**
     * Replace a cache entry.
     * @param	objectId	The object id.
     * @param	object		The object instance.
     */
	public synchronized void putObject(String objectId, T object) {
		CacheEntry entry = objectMap.get(objectId);
		if (entry != null) {
			// replace since this is a more recent update
			entry.unlink();
		} else { 
			++length;
		}
		objectMap.put(objectId, pushFront(new CacheEntry(object, objectId)));
	}
	
    /**
     * Return a LRU cache entry.
     * @param	objectId	The object id.
     * @param	object		The object instance.
     */
	public synchronized void putObjectLRU(String objectId, T object) {
		CacheEntry entry = objectMap.get(objectId);
		if (entry != null) {
			// don't replace if more recent update exists
			return;
		} else { 
			++length;
		}
		objectMap.put(objectId, pushBack(new CacheEntry(object, objectId)));
	}
	
    /**
     * Remove the least recently used cache entry
     * @param	objectId	The object id.
     * @param	object		The object instance.
     */
	public synchronized T removeLRU() {
		CacheEntry entry = popBack();
		if (entry == null)
			return null;
		--length;
		T o = entry.object;
		objectMap.remove(entry.id);
		return o;
	}
	
	/**
	 * Get the object instance.
     * @param	objectId	The object id.
	 * @return	The object instance if it exists else null.
	 */
	public synchronized T getObject(String objectId) {
		CacheEntry entry = objectMap.get(objectId);
		if (entry == null)
			return null;
		// Make MRU
		return pushFront(entry.unlink()).object;
	}

	/**
	 * Get a clone of the object instance.
     * @param	objectId	The object id.
	 * @return	A clone of the object instance if it exists else null.
	 * @throws	CloneNotSupportedException if the object is not cloneable.
	 */
	@SuppressWarnings("unchecked")
	public synchronized T cloneObject(String objectId) throws CloneNotSupportedException {
		if (cloneMethod == null)
			throw new CloneNotSupportedException();
		CacheEntry entry = objectMap.get(objectId);
		try {
			if (entry != null)
				return (T) cloneMethod.invoke(entry.object);
		} catch (IllegalAccessException | IllegalArgumentException
				| InvocationTargetException e) {
		}
		return null;
	}
	
	public void transferCache(ObjectCache<T> other) {
		
		HashMap<String, CacheEntry> otherMap;
	    CacheEntry otherList;
	    int otherLength;
	    
		synchronized(other) {
			otherMap = other.objectMap;
			otherList = other.list;
			otherLength = other.length;
			other.objectMap = new HashMap<String, CacheEntry>();
			other.list = new CacheEntry();
			other.length = 0;
		}

		synchronized(this) {
			this.objectMap = otherMap;
			this.list = otherList;
			this.length = otherLength;
		}
	}
	
}
