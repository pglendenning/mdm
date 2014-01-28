package com.mdm.scep;

import java.security.cert.X509CRL;
import java.util.Date;

/**
 * Root Certificate Authorities are created with a revocation for each month until
 * expiration. This way we can always revoke a CA if it is compromised even when
 * the private key has been lost. This can happen for example if the device
 * securing the private key is stolen or lost.
 * @author paul
 */
public class RootCertificateAuthorityRevokePoint {
	
	private	Date	notBefore;	// Not valid < 
	private Date	notAfter;	// Not valid >=
	private X509CRL	crlst;

	/**
	 * Construct a revocation point.
	 * @param validFrom	The date after which the revocation is valid.
	 * @param validTo	The date after which the revocation is invalid.
	 * @param crl		The certificate revocation list.
	 */
	public RootCertificateAuthorityRevokePoint(Date validFrom, Date validTo, X509CRL crl) {
		notBefore = validFrom;
		notAfter = validTo;
		crlst = crl;
	}

	/**
	 * Get the date after which the revocation is valid.
	 * @return	The not before date.
	 */
	public Date getNotBefore() {
		return notBefore;
	}
	
	/**
	 * Get the date after which the revocation is invalid.
	 * @return	The not after date.
	 */
	public Date getNotAfter() {
		return notAfter;
	}
	
	/**
	 * Get the certificate revocation list.
	 * @return	The x509 certificate revocation list.
	 */
	public X509CRL getCRL() {
		return crlst;
	}
}
