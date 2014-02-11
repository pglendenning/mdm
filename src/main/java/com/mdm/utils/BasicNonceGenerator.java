/**
 * 
 */
package com.mdm.utils;

/**
 * @author paul
 *
 */
public class BasicNonceGenerator extends NonceGenerator {

	/* (non-Javadoc)
	 * @see com.mdm.utils.NonceGenerator#storeNonce(java.lang.String, long)
	 */
	@Override
	void storeNonce(String nonce, long expireAt) {
		// does nothing
	}

}
