package com.mdm.auth;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.mdm.auth.PasscodeGenerator.Signer;

/**
 * Time code signer with key. The key allows independent time code
 * generators sync'd to a common clock.
 * @author paul
 */
public class TimecodeSigner implements Signer {
	private Mac mac;
	public TimecodeSigner(Mac mac, String key) throws InvalidKeyException, UnsupportedEncodingException {
		this.mac = mac;
		mac.init(new SecretKeySpec(key.getBytes("UTF-8"), mac.getAlgorithm()));
	}
	
	public TimecodeSigner(String key) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
		this.mac = Mac.getInstance("HmacSHA1");
		mac.init(new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA1"));
	}
	
	@Override
	public byte[] sign(byte[] data) throws GeneralSecurityException {
		return mac.doFinal(data);
	}
}

