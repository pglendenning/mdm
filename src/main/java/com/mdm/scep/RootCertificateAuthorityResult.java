package com.mdm.scep;

import java.security.cert.X509Certificate;

/**
 * Simple holder for a RootCertificateAuthority result.
 * @author paul
 */
public class RootCertificateAuthorityResult {
	
	private RootCertificateAuthority rootCA;
	private X509Certificate issuedCert;

	/**
	 * Constructor.
	 */
	RootCertificateAuthorityResult(RootCertificateAuthority ca, X509Certificate cert) {
		rootCA = ca;
		issuedCert = cert;
	}
	
	/**
	 * Get the CA. This should not be NULL.
	 * @return
	 */
	RootCertificateAuthority getCa() {
		return rootCA;
	}
	
	/**
	 * Get the issued certificate. Maybe null.
	 * @return
	 */
	X509Certificate getIssuedCertificate() {
		return issuedCert;
	}
}
