/**
 * 
 */
package com.mdm.utils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Calendar;

/**
 * @author paul
 *
 */
public abstract class NonceGenerator {
	
	abstract void storeNonce(String nonce, long expireAt);
	
	private SecureRandom random = new SecureRandom();
	
	/**
	 * Create a random string.
	 * @param timeToExpire	Validity time in seconds
	 * @return	A nonce.
	 */
	public String createNonce(int timeToExpire) {
        Calendar now = Calendar.getInstance();
        now.add(Calendar.SECOND, timeToExpire);
        String n = new BigInteger(130, random).toString(32);
        storeNonce(n, now.getTime().getTime() - now.getTimeZone().getRawOffset()/1000);
        return n;		
	}
	
	/**
	 * Create a random string.
	 * @return	A nonce.
	 */
	public String createNonce() {
        String n = new BigInteger(130, random).toString(32);
        storeNonce(n, 0);
        return n;
	}
}
