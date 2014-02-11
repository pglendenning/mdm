package com.mdm.cert;

import java.security.cert.X509Certificate;

/**
 * Simple holder for a CertificateAuthority result.
 * @author paul
 */
public class IssuedCertificateResult {
	
	private CertificateAuthority rootCA;
	private X509Certificate issuedCert;
	private String objectId;

	/**
	 * Constructor.
	 */
	IssuedCertificateResult(CertificateAuthority ca, X509Certificate cert, String id) {
		rootCA = ca;
		issuedCert = cert;
		objectId = id;
	}
	
	/**
	 * Get the CA. This should not be NULL.
	 * @return
	 */
	public CertificateAuthority getCa() {
		return rootCA;
	}
	
	/**
	 * Get the object id.
	 * @return
	 */
	public String getObjectId() {
		return objectId;
	}
	
	/**
	 * Get the issued certificate. Maybe null.
	 * @return
	 */
	public X509Certificate getIssuedCertificate() {
		return issuedCert;
	}
	
	/**
	 * Revoke an issued certificate.
	 */
	public void revokeIssued() {
		
	}
	

}
