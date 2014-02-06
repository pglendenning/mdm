/**
 * 
 */
package com.mdm.api;

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
	
    private CacheEntry push(CacheEntry newItem) {
		assert !newItem.isLinked();
		newItem.next = list.next;
		newItem.prev = list.curr;
		list.next.get().prev = newItem.curr;
		list.next = newItem.curr;
		return newItem;
	}
	
    // Remove the least recently used entry
    private CacheEntry pop() {
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
			// replace
			entry.unlink();
		} else { 
			++length;
		}
		objectMap.put(objectId, push(new CacheEntry(object, objectId)));
	}
	
    /**
     * Remove the least recently used cache entry
     * @param	objectId	The object id.
     * @param	object		The object instance.
     */
	public synchronized T removeLRU() {
		CacheEntry entry = pop();
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
		return push(entry.unlink()).object;
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
}
