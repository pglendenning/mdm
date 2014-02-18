package com.mdm.api;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.mdm.auth.PasscodeGenerator;
import com.mdm.auth.PasscodeGenerator.Passcode;
import com.mdm.cert.CertificateAuthority;

/**
 * Class holding the enrollment state of a device. 
 * @author paul
 */
public class EnrollmentHolder {
	// Enrollment states
	/** Enrollment started but not authorized */
	public static final int E_STARTED = 0;
	/** Enrollment authorized. */
	public static final int E_AUTHORIZED = 1;
	/** iOS Device Waiting for CSR to be fulfilled. */
	public static final int E_DEVICE_WAITING_CSR = 2;
	/** iOS Device CSR fulfilled. */
	public static final int E_DEVICE_COMPLETED_CSR = 3;
	/** iOS Device enrollment complete */
	public static final int E_DEVICE_DONE = 4;
	/** Client App Waiting for CSR to be fulfilled. */
	public static final int E_CLIENT_WAITING_CSR = 5;
	/** Client App CSR fulfilled. */
	public static final int E_CLIENT_COMPLETED_CSR = 6;
	/** Enrollment cancelled */
	public static final int E_CANCELLED = 7;
	/** Enrollment completed. */
	public static final int E_DONE = 8;
	/** Enrollment error */
	public static final int E_FAILED = 9;
	/** Maximum number of intervals between a status update */
	public static final int maxIntervalsBetweenStatusUpdate = 2;
	
	private String enrollId = null;
	private String parentId = null;
	private String enrollURL = null;
	private long[] serialNums = null;
	private PasscodeGenerator otpGenerator = null;
	private PKCS10CertificationRequest signingRequest = null;
	private CertificateAuthority signingCa = null;
	private X509Certificate signedRequest = null;
	private String authorizedOTP = null;
	private int state = E_STARTED;	
	private int lastState = -1;
	private long timestamp = 0;

	public EnrollmentHolder(String parentId, CertificateAuthority parentCA, String enrollId, 
			long serialNum1, long serialNum2, String enrollURL, PasscodeGenerator otpGenerator) throws NoSuchAlgorithmException {
		this.state = E_STARTED;
		this.enrollId = enrollId;
		this.parentId = parentId;
		this.signingCa = parentCA;
		this.serialNums = new long[2];
		this.serialNums[0] = serialNum1;
		this.serialNums[1] = serialNum2;
		this.enrollURL = enrollURL;
		this.otpGenerator = otpGenerator;
	}

	// Not threadsafe
	private void updateTimestamp() {
		if (state != E_FAILED && state != E_CANCELLED && state != E_DONE)
			timestamp = System.currentTimeMillis() / 1000;
	}
	
	// Not threadsafe
	private void fail() {
		updateTimestamp();
		state = E_FAILED;
		signingRequest = null;
		signedRequest = null;
		signingCa = null;		
	}
	
	// Not threadsafe
	private void cancel() {
		updateTimestamp();
		state = E_CANCELLED;
		signingRequest = null;
		signedRequest = null;
		signingCa = null;		
	}
	
	/**
	 * Check if the object has been modified.
	 */
	public synchronized boolean isModified() {
		return lastState != state;
	}
	
	/**
	 * Clear the modified state
	 */
	public synchronized void clearModified() {
		lastState = state;
	}
	
	/**
	 * Get the number of seconds that have passed since the enrollment was
	 * completed, or cancelled.
	 * @return
	 */
	public synchronized long getTimeSinceCompleted() {
		if (state != E_FAILED && state != E_CANCELLED && state != E_DONE)
			return 0;
		return System.currentTimeMillis() / 1000 - timestamp;
	}
	
	/**
	 * @return	The enrollment URL.
	 */
	public String getEnrollURL() {
		return enrollURL;
	}
	
	/**
	 * @return	The parent id.
	 */
	public String getParentId() {
		return parentId;
	}
	
	/**
	 * @return	The enrollment id.
	 */
	public String getEnrollId() {
		return enrollId;
	}
	
	/**
	 * @return	An array of 2 serial numbers
	 */
	public long[] getSerialNums() {
		return serialNums;
	}
	
	/**
	 * Get the authorized one time password.
	 * @return	The one time password.
	 */
	public synchronized String getAuthorizedOTP() {
		return authorizedOTP;
	}
	
	/**
	 * @return	True if the device and client app are enrolled, false if enrollment is pending.
	 */
	public synchronized boolean isEnrolled() {
		return state == E_DONE;
	}
	
	/**
	 * @return	True if the device is enrolled.
	 */
	public synchronized boolean isDeviceEnrolled() {
		return state == E_DEVICE_DONE || state == E_CLIENT_WAITING_CSR ||
				state == E_CLIENT_COMPLETED_CSR || state == E_DONE;
	}
	
	/**
	 * @return	True if the enrollment is cancelled.
	 */
	public synchronized boolean isCancelled() {
		return state == E_CANCELLED || state == E_FAILED;
	}
	
	public synchronized boolean isWaitingCSR() {
		return state == E_DEVICE_WAITING_CSR || state == E_CLIENT_WAITING_CSR;
	}
	
	public synchronized boolean isCompletedCSR() {
		return state == E_DEVICE_COMPLETED_CSR || state == E_CLIENT_COMPLETED_CSR;		
	}
	
	public synchronized boolean isAuthorized() {
		return state == E_AUTHORIZED;
	}
	
	/**
	 * Authorize using a one time password.
	 * @param	otp		The one time password.
	 * @return	True if authorize succeeded.
	 * @throws	OperationNotAllowedException if the operation is not allowed.
	 * @throws	GeneralSecurityException if an error occurs verify the one time password.
	 */
	public synchronized boolean authorize(String otp) throws OperationNotAllowedException, GeneralSecurityException {
		if (state != E_STARTED)
			throw new OperationNotAllowedException();
		boolean auth = false;
		try {
			auth = otpGenerator.verifyTimeoutCode(otp);
		} catch (GeneralSecurityException e) {
			fail();
			throw e;
		}
		if (auth) {
			authorizedOTP = otp;
			state = E_AUTHORIZED;
		}
		return auth;
	}
	
	/**
	 * Get the certificate signing request.
	 * @return	The PKCS10 container.
	 * @throws	OperationNotAllowedException if there is no signing request available.
	 * @throws	InternalErrorException if an internal error occurred. 
	 */
	public synchronized PKCS10CertificationRequest getCSR() throws OperationNotAllowedException, InternalErrorException {
		if (!isWaitingCSR())
			throw new OperationNotAllowedException();
		if (signingRequest == null)
			throw new InternalErrorException();	// will cause HTTP 500
		return signingRequest;
	}
	
	/**
	 * Initiate a certificate signing request. This method is called by the client
	 * app in response to a successful enrollment.
	 * @param	csr		The request to sign.
	 * @param 	caCert	The signers public certificate.
	 * @throws	OperationNotAllowedException if the request cannot be initiated.
	 */
	public synchronized void clientInitiateCSR(PKCS10CertificationRequest csr) throws OperationNotAllowedException {
		if (state != E_DEVICE_DONE)
			throw new OperationNotAllowedException();
		
		// TODO: csr.isSignatureValid(verifierProvider)
		signingRequest = csr;
		state = E_CLIENT_WAITING_CSR;
	}
	
	/**
	 * Initiate a certificate signing request. This method is called by the SCEP
	 * server in response to a org.jscep.client.Client.enrol().
	 * @param	csr		The request to sign.
	 * @param 	caCert	The signers public certificate.
	 * @throws	OperationNotAllowedException if the request cannot be initiated.
	 */
	public synchronized void scepInitiateCSR(PKCS10CertificationRequest csr) throws OperationNotAllowedException {
		if (state != E_AUTHORIZED)
			throw new OperationNotAllowedException();
		
		// TODO: csr.isSignatureValid(verifierProvider)
		signingRequest = csr;
		state = E_DEVICE_WAITING_CSR;
	}
	
	/**
	 * Complete a certificate signing request. Called from the REST API in response to
	 * a parent device fulfilling the CSR.
	 * @param	cert	The signed certificate.
	 * @throws	OperationNotAllowedException if there is no signing request to complete.
	 * @throws	OperationFailedException if the request could not be completed.
	 * @throws	InternalErrorException if an internal error occurred. 
	 */
	public synchronized void completeCSR(X509Certificate cert) throws OperationNotAllowedException, OperationFailedException, InternalErrorException {
		if (!isWaitingCSR())
			throw new OperationNotAllowedException();
		
		if (signingRequest == null || signingCa == null) {
			fail();
			throw new InternalErrorException();	// will cause HTTP 500
		}
		
    	try {
    		long sn;
    		// Check signature and expiration date
			cert.verify(signingCa.getCaCertificate().getPublicKey());
		    cert.checkValidity(new Date());
			// Check serial number
			sn = cert.getSerialNumber().longValue();
			if (sn != 0 && sn == serialNums[0])
				serialNums[0] = 0; // clear once used
			else if (sn != 0 && sn == serialNums[1])
				serialNums[1] = 0;
			else {
				fail();
				throw new OperationFailedException(); 				
			}
			// TODO: Verify the signing request has the same fields as the certificate
			// At a minimum we must ensure OU=enrollId.
		} catch (InvalidKeyException | CertificateException
				| NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			// Bad signature, enrollment failed
			fail();
			throw new OperationFailedException(); 
		}
   
		signingRequest = null;
		signedRequest = cert;
		
		if (state == E_DEVICE_WAITING_CSR) {
			state = E_DEVICE_COMPLETED_CSR;
		} else { // therefore state == E_CLIENT_WAITING_CSR
			state = E_CLIENT_COMPLETED_CSR;
		}
	}
	
	/**
	 * Close a certificate signing request and return the X509 certificate. Called
	 * by the client app server after a successful SCEP enrollment.
	 * @return	The signed X509 certificate.
	 * @throws	OperationNotAllowedException if there is no signing request to complete.
	 * @throws	InternalErrorException if an internal error occurred. 
	 */
	public synchronized X509Certificate clientCloseCSR() throws OperationNotAllowedException, InternalErrorException {
		// Can only call if we have completed a CSR
		if (state != E_CLIENT_COMPLETED_CSR)
			throw new OperationNotAllowedException();

		if (signingCa == null) {
			// Expect a signed certificate it the CSR is completed
			fail();
			throw new InternalErrorException();	// will cause HTTP 500
		}
			
		X509Certificate cert = signedRequest;
		if (cert != null) {
			updateTimestamp();
			state = E_DONE;
			signingRequest = null;
			signedRequest = null;
		}

		return cert;
	}

	/**
	 * Close a certificate signing request and return the X509 certificate. Called
	 * by the SCEP server on a poll operation.
	 * @return	The signed X509 certificate.
	 * @throws	OperationNotAllowedException if there is no signing request to complete.
	 * @throws	InternalErrorException if an internal error occurred. 
	 */
	public synchronized X509Certificate scepCloseCSR() throws OperationNotAllowedException, InternalErrorException {
		// Can only call if we have completed a CSR
		if (state != E_DEVICE_COMPLETED_CSR)
			throw new OperationNotAllowedException();

		if (signingCa == null) {
			// Expect a signed certificate it the CSR is completed
			fail();
			throw new InternalErrorException();	// will cause HTTP 500
		}
			
		X509Certificate cert = signedRequest;
		if (cert != null) {
			updateTimestamp();
			state = E_DEVICE_DONE;
			signingRequest = null;
			signedRequest = null;
		}
		return cert;
	}

	/**
	 * Get the enrollment status for this holder.
	 * @return	The enrollment status.
	 */
	public synchronized EnrollStatusResponseData getEnrollStatus() {
		// Do cancel first just in case generateTimeoutCode() keeps failing
		if (isCancelled())
			return new EnrollStatusResponseData(isEnrolled(), EnrollStatusResponseData.DO_CANCEL, otpGenerator.getZeroCode(), 0);
		
		Passcode otp = null;
		try {
			otp = otpGenerator.generateTimeoutCode();
		} catch (GeneralSecurityException e) {
			fail();
			return new EnrollStatusResponseData(isEnrolled(), EnrollStatusResponseData.DO_CANCEL, otpGenerator.getZeroCode(), 0);
		}
		
		// Cancel enrollment if status update nor requested frequently
		if (otp.getIntervalsPassed() > maxIntervalsBetweenStatusUpdate) {
			cancel();
			return new EnrollStatusResponseData(isEnrolled(), EnrollStatusResponseData.DO_CANCEL, otpGenerator.getZeroCode(), 0);
		}
			
		int action = EnrollStatusResponseData.DO_NOTHING;	// do nothing/otp update
		if (isWaitingCSR())
			action = EnrollStatusResponseData.DO_CSR;		// fulfill CSR
		return new EnrollStatusResponseData(isEnrolled(), action, otp.getPasscode(), otp.getNextUpdate());
	}
}
