/*
 * Original source taken from http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
 * Author Svetlin Nakov
 */
package com.mdm.utils;

import java.security.cert.PKIXCertPathBuilderResult;

/**
 * This class keeps the result from the certificate verification process.
 */
public class CertificateVerificationResult {
	private boolean valid;
	private PKIXCertPathBuilderResult result;
	
	/**
	 * Constructs a certificate verification result for valid
	 * certificate by given certification path.
	 */
	public CertificateVerificationResult(PKIXCertPathBuilderResult result, boolean valid) {
		this.valid = valid;
		this.result = result;
	}

	/**
	 * Get the verification validity status.
	 * @return True if the verifications was successful
	 */
	public boolean isValid() {
		return valid;
	}

	/**
	 * Get the trust anchor path.
	 * @return The trust anchor path
	 */
	public PKIXCertPathBuilderResult getResult() {
		return result;
	}
}
