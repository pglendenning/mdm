/**
 * 
 */
package com.mdm.api.test;

import static org.junit.Assert.*;

import org.junit.Test;

import com.mdm.api.ObjectCache;

/**
 * @author paul
 *
 */
public class ObjectCacheTest {

	@Test
	public void testCache() {
		
		ObjectCache<Integer> cache = new ObjectCache<Integer>();
		
		// ADD OBJECTS
		cache.putObject("A", new Integer(1));
		cache.putObject("B", new Integer(2));
		cache.putObject("C", new Integer(3));
		cache.putObject("D", new Integer(4));
		
		assertTrue(cache.getObject("A").equals(new Integer(1)));
		assertTrue(cache.getObject("B").equals(new Integer(2)));
		assertTrue(cache.getObject("C").equals(new Integer(3)));
		assertTrue(cache.getObject("D").equals(new Integer(4)));
		
		// REPLACE OBJECTS
		cache.putObject("A", new Integer(5));
		cache.putObject("B", new Integer(6));
		assertTrue(cache.getObject("C").equals(new Integer(3)));
		assertTrue(cache.getObject("D").equals(new Integer(4)));
		assertTrue(cache.getObject("A").equals(new Integer(5)));
		assertTrue(cache.getObject("B").equals(new Integer(6)));

		// REMOVE OBJECTS
		assertTrue(cache.getLength() == 4);
		assertTrue(cache.removeLRU().equals(new Integer(3)));
		assertTrue(cache.removeLRU().equals(new Integer(4)));
		assertTrue(cache.removeLRU().equals(new Integer(5)));
		assertTrue(cache.removeLRU().equals(new Integer(6)));
		assertTrue(cache.removeLRU() == null);
		assertTrue(cache.getLength() == 0);
		assertTrue(cache.isEmpty());
	}
}
