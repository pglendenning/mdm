package com.mdm.auth;

/*
 * Original code https://github.com/mclamp/JAuth
 * @author sweis@google.com (Steve Weis)
 */

import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;

/**
 * An implementation of the HOTP generator specified by RFC 4226. Generates
 * short passcodes that may be used in challenge-response protocols or as
 * timeout passcodes that are only valid for a short period.
 *
 * The default passcode is a 6-digit decimal code and the default timeout
 * period is 1 minute.  The default validity window for the passcode +/- 20secs.
 * 
 * This class is thread safe.
 */
public class PasscodeGenerator {
	/** Default decimal passcode length */
	private static final int PASS_CODE_LENGTH = 6;

	/** 
	 * Default validity window (in seconds) for the timecode. The timecode is
	 * valid for the current time +/- VALIDITY_PERIOD.
	 */
	private static final int VALIDITY_PERIOD = 20;
	
	/** Default timecode update interval period in seconds. */
	private static final int INTERVAL_PERIOD = 60;

	private static final int PIN_MODULO = (int) Math.pow(10, PASS_CODE_LENGTH);

	private final Signer signer;
	private final int codeLength;
	private final int intervalPeriod;
	private final int validityPeriod;
	private long lastInterval;
	
	/**
	 * Time pass code atomic return value.
	 * @author Paul Glendenning
	 */
	public class Passcode {
		private String passcode;
		private int nextUpdate;
		private long intervalsPassed;
		
		Passcode(String passcode, int nextUpdate, long intervalsPassed) {
			this.passcode = passcode;
			this.nextUpdate = nextUpdate;
			this.intervalsPassed = intervalsPassed;
		}
		
		/** The passcode */
		public String getPasscode() {
			return passcode;
		}
		
		/** The number of seconds until the next update */
		public int getNextUpdate() {
			return nextUpdate;
		}
		
		/** The intervals passed since last update */
		public long getIntervalsPassed() {
			return intervalsPassed;
		}
	}

	/**
	 * Using an interface to allow us to inject different signature
	 * implementations.
	 */
	interface Signer {
		byte[] sign(byte[] data) throws GeneralSecurityException;
	}
	
	/**
	 * @param mac A {@link Mac} used to generate passcodes
	 */
	public PasscodeGenerator(Mac mac) {
		this(mac, PASS_CODE_LENGTH, INTERVAL_PERIOD, VALIDITY_PERIOD);
	}

	/**
	 * @param	mac				A {@link Mac} used to generate passcodes
	 * @param	passCodeLength	The length of the decimal passcode. Use -1 for default length.
	 * @param	intervalPeriod	The interval period between passcode updates. Use -1 for default interval.
	 * @param	validityPeriod	The +/- time error margin (in seconds) for passcode validity. Use -1 for default validity.
	 */
	public PasscodeGenerator(final Mac mac, int passCodeLength, int intervalPeriod, int validityPeriod) {
		this(new Signer() {
			public byte[] sign(byte[] data){
				return mac.doFinal(data);
			}
		}, (passCodeLength>0)?passCodeLength:PASS_CODE_LENGTH, 
		   (intervalPeriod>0)?intervalPeriod:INTERVAL_PERIOD,
		   (validityPeriod>0)?validityPeriod:VALIDITY_PERIOD);
	}

	/**
	 * @param	signer			A signer implementing the Signer interface.
	 * @param	passCodeLength	The length of the decimal passcode. Use -1 for default length.
	 * @param	intervalPeriod	The interval period between passcode updates. Use -1 for default interval.
	 * @param	validityPeriod	The +/- time error margin (in seconds) for passcode validity. Use -1 for default validity.
	 */
	public PasscodeGenerator(Signer signer, int passCodeLength, int intervalPeriod, int validityPeriod) {
		this.signer = signer;
		this.codeLength = (passCodeLength>0)?passCodeLength:PASS_CODE_LENGTH;
		this.intervalPeriod = (intervalPeriod>0)?intervalPeriod:INTERVAL_PERIOD;
		this.validityPeriod = (validityPeriod>0)?validityPeriod:VALIDITY_PERIOD;
		this.lastInterval = getInterval(clock.getTime());
	}

	private String padOutput(int value) {
		String result = Integer.toString(value);
		for (int i = result.length(); i < codeLength; i++) {
			result = "0" + result;
		}
		return result;
	}
	
	/**
	 * Return a passcode with all zeros
	 * @return
	 */
	public String getZeroCode() {
		return padOutput(0);
	}

	/**
	 * @return	A decimal timeout code
	 */
	public Passcode generateTimeoutCode() throws GeneralSecurityException {
		long time = clock.getTime();
		long interval = time / intervalPeriod;
		long intervalsPassed = interval - lastInterval;
		lastInterval = interval;
		return new Passcode(generateResponseCode(interval), (int)(time % intervalPeriod), intervalsPassed);
	}

	/**
	 * @param	challenge	A long-valued challenge
	 * @return	A decimal response code
	 * @throws	GeneralSecurityException If a JCE exception occur
	 */
	public String generateResponseCode(long challenge)
			throws GeneralSecurityException {
		byte[] value = ByteBuffer.allocate(8).putLong(challenge).array();
		return generateResponseCode(value);
	}

	/**
	 * Note: Signer must use HmacSHA1 algorithm.
	 * @param	challenge	An arbitrary byte array used as a challenge
	 * @return	A decimal response code
	 * @throws	GeneralSecurityException If a JCE exception occur
	 */
	public String generateResponseCode(byte[] challenge)
			throws GeneralSecurityException {
		byte[] hash;
		synchronized(this) {
			hash = signer.sign(challenge);
		}
		// Dynamically truncate the hash
		// OffsetBits are the low order bits of the last byte of the hash
		int offset = hash[hash.length - 1] & 0xf; // Only works with HmacSHA1
		// Grab a positive integer value starting at the given offset.
		int truncatedHash = hashToInt(hash, offset) & 0x7FFFFFFF;
		int pinValue = truncatedHash % PIN_MODULO;
		return padOutput(pinValue);
	}

	/**
	 * Grabs a positive integer value from the input array starting at
	 * the given offset.
	 * @param	bytes	The array of bytes
	 * @param	start	The index into the array to start grabbing bytes
	 * @return	The integer constructed from the four bytes in the array
	 */
	private int hashToInt(byte[] bytes, int start) {
		DataInput input = new DataInputStream(
				new ByteArrayInputStream(bytes, start, bytes.length - start));
		int val;
		try {
			val = input.readInt();
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
		return val;
	}

	/**
	 * Get the number of seconds between each update.
	 * @return	The time in seconds.
	 */
	public int getIntervalPeriod() {
		return intervalPeriod;
	}
	
	/**
	 * Get the interval given an offset in seconds form the current time.
	 * @param	offset	The time offset in seconds.
	 * @return	The interval.
	 */
	private long getInterval(long time) {
		return time / intervalPeriod;
	}
	
	/**
	 * @param	challenge	A challenge to check a response against
	 * @param	response	A response to verify
	 * @return	True if the response is valid
	 */
	public boolean verifyResponseCode(long challenge, String response)
			throws GeneralSecurityException {
		String expectedResponse = generateResponseCode(challenge);
		return expectedResponse.equals(response);
	}

	/**
	 * Verify a timeout code. The timeout code will be valid for a time
	 * determined by the interval period and the validity window
	 *
	 * @param	timeoutCode	The timeout code
	 * @return	True if the timeout code is valid
	 */
	public boolean verifyTimeoutCode(String timeoutCode)
			throws GeneralSecurityException {
		return verifyTimeoutCode(timeoutCode, validityPeriod, validityPeriod);
	}

	/**
	 * Verify a timeout code. The timeout code will be valid for a time
	 * determined by the interval period and the number of +/- error
	 * margin (in seconds) for timeout code validity.
	 *
	 * @param	timeoutCode	The timeout code
	 * @param	pastValid 	The number of past seconds to check
	 * @param 	futureValid	The number of future seconds to check
	 * @return	True if the timeout code is valid
	 */
	public boolean verifyTimeoutCode(String timeoutCode, int pastValid,
			int futureValid) throws GeneralSecurityException {
		long time = clock.getTime();
		for (long i=getInterval(time-pastValid), imax=getInterval(time+futureValid); i <= imax; i++) {
			String expectedResponse = generateResponseCode(i);
			if (expectedResponse.equals(timeoutCode)) {
				return true;
			}
		}
		return false;
	}

	private IntervalClock clock = new IntervalClock() {
		/*
		 * @return The current time in seconds
		 */
		public long getTime() {
			return System.currentTimeMillis() / 1000;			
		}
	};

	/**
	 * To facilitate injecting a mock clock.
	 */
	interface IntervalClock {
		public long getTime();
	}
}
