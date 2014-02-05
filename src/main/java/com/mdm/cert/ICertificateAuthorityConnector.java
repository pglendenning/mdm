/**
 * 
 */
package com.mdm.cert;

import java.security.cert.X509CRL;
import java.util.Date;

/**
 * @author paul
 *
 */
public interface ICertificateAuthorityConnector {
	
	/**
	 * Get a new certificate store instance
	 * @return	The certificate store.
	 */
	ICertificateAuthorityStore getStoreInstance();

	/**
	 * Get the object id for this CA.
	 * @return	The object id.
	 */
	public String getObjectId();

	/**
	 * Add the CA CRL for the given date range.
	 * 
	 * @param	notBefore	The revocation begin date.
	 * @param	notBefore	The revocation end date.
	 * @return	The certificate revocation list.
	 */
	public void addCaCRL(Date notBefore, Date notafter, X509CRL crl);
	
	/**
	 * Get the CA CRL.
	 * 
	 * @return	The certificate revocation list. An empty CRL is returned if the
	 * 			CA certificate has not been revoked.
	 */
	public X509CRL getCaCRL();
	
	/**
	 * Get the Issued CRL.
	 * 
	 * @return	The certificate revocation list. An empty CRL is returned is no
	 * 			revocations have occurred.
	 */
	public X509CRL getIssuedCRL();
	
	/**
	 * Disable/enable a root certificate authority. A disabled authority will not
	 * return a result for a IRootCertificateAuthorityStore.getCA() or 
	 * IRootCertificateAuthorityStore.getIssued().
	 * 
	 * @return	True if the account is active.
	 */
	public boolean isEnabled();
	
	/**
	 * Set the enabled state. The enabled state reflects whether the account is
	 * active or suspended.
	 */
	public void setEnabled(boolean enableState);

	/**
	 * Get the next serial number for signing a certificate. The serial number
	 * is incremented as a result of this call.
	 * 
	 * @return	The next serial number.
	 * @throws CertificateAuthorityException 
	 */
	public long getNextSerialNumber() throws CertificateAuthorityException;

}
