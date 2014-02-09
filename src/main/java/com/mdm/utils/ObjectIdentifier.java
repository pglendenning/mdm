package com.mdm.utils;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Generic object identifier - a unique random string [a-zA-Z0-9]+
 * @author Paul Glendenning
 */

public class ObjectIdentifier {
	private static SecureRandom generator = new SecureRandom();
	private final static int ID_LENGTH = 32;

	/*
	 * Private constructor. use getInstance()
	 */
	private ObjectIdentifier() {
	}
	
	/**
	 * Create an object identifier string.
	 * @return	The object id string.
	 */
	public static String getInstance() {
		//                      0         1         2         3 
		//                      01234567890123456789012345678901
		// 5-bits per character 0123456789abcdefghijklmnpqrstuvw
		return new BigInteger(ID_LENGTH*5, generator).toString(32);
	}
	
	/**
	 * Create an object identifier string.
	 * @param	length	A positive integer length.
	 * @return	The object id string.
	 */
	public static String getInstance(int length) {
		//                      0         1         2         3 
		//                      01234567890123456789012345678901
		// 5-bits per character 0123456789abcdefghijklmnpqrstuvw
		if (length <= 0)
			throw new IllegalArgumentException();

		return new BigInteger(length*5, generator).toString(32);
	}
}
