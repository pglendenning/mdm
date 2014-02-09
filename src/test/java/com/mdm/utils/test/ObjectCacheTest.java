/**
 * 
 */
package com.mdm.utils.test;

import static org.junit.Assert.*;

import org.junit.Test;

import com.mdm.utils.ObjectCache;

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
	
	@Test
	public void testTransfer() {

		ObjectCache<Integer> cache1 = new ObjectCache<Integer>();
		ObjectCache<Integer> cache2 = new ObjectCache<Integer>();
		
		// ADD OBJECTS
		cache1.putObject("A", new Integer(1));
		cache1.putObject("B", new Integer(2));
		cache1.putObject("C", new Integer(3));
		cache1.putObject("D", new Integer(4));	
		assertTrue(cache1.getLength() == 4);

		// TRANSFER TO SELF DOES NOTHING
		assertTrue(cache1.getLength() == 4);
		cache1.transferCache(cache1);
		assertTrue(cache1.getLength() == 4);
		assertTrue(cache1.removeLRU().equals(new Integer(1)));
		assertTrue(cache1.removeLRU().equals(new Integer(2)));
		assertTrue(cache1.removeLRU().equals(new Integer(3)));
		assertTrue(cache1.removeLRU().equals(new Integer(4)));
		assertTrue(cache1.getLength() == 0);

		cache1.putObject("A", new Integer(1));
		cache1.putObject("B", new Integer(2));
		cache1.putObject("C", new Integer(3));
		cache1.putObject("D", new Integer(4));
		assertTrue(cache1.getLength() == 4);
		
		// TRANSFER TO OTHER CLEARS SELF
		cache2.transferCache(cache1);
		assertTrue(cache1.getLength() == 0);
		assertTrue(cache2.getLength() == 4);
		assertTrue(cache2.removeLRU().equals(new Integer(1)));
		assertTrue(cache2.removeLRU().equals(new Integer(2)));
		assertTrue(cache2.removeLRU().equals(new Integer(3)));
		assertTrue(cache2.removeLRU().equals(new Integer(4)));
	}
}
