package com.mdm.scep;

import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;

/**
 * The RootCertificateAutorityConnector provides connection between the data
 * store and the RootCertificateAuthority class. It models a single row in 
 * a query.
 * @author paul
 */
public interface IRootCertificateAuthorityConnector {
	
	/**
	 * Get the store associated with this certificate authority.
	 */
	public IRootCertificateAuthorityStore getStore();
	
	/**
	 * Get the self signed root certificate for this CA.
	 * @return	The root certificate.
	 */
	public X509Certificate getCaCertificate();

	/**
	 * Get the object id for this CA.
	 * @return	The object id.
	 */
	public String getObjectId();

	/**
	 * Get the registration authority certificate for this CA.
	 * @return	The registration authority certificate.
	 */
	public X509Certificate getRaCertificate();

	/**
	 * Get the registration authority certificate for this CA.
	 * @return	The registration authority certificate.
	 */
	public PrivateKey getRaPrivateKey();

	/**
	 * Get the CA CRL for the given date.
	 * 
	 * @param	date	The revocation date.
	 * @return	The certificate revocation list.
	 */
	public X509CRL getCaCRL(Date date);
	
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
	 * Get the list of all certificate serial numbers issued by this CA
	 * @return	The list of serial numbers.
	 */
	public List<IssuerAndSerialNumber> getIssuedList();
}
