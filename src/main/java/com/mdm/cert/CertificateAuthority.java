package com.mdm.cert;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * The RootCertificateAutority is used by SCEP to manage certificates associated with
 * each account. For family MDM  the root will be the parents certificate identify.
 * @author paul
 */
public class CertificateAuthority {
	private ICertificateAuthorityConnector connector;
	private X509Certificate caCert = null;
	private X509Certificate raCert = null;
	private PrivateKey raKey = null;
	
	
	CertificateAuthority(ICertificateAuthorityConnector connector, X509Certificate caCert, X509Certificate raCert, PrivateKey raKey) {
		this.connector = connector;
		this.caCert = caCert;
		this.raCert = raCert;
		this.raKey = raKey;
	}
	
	/**
	 * Certificate store getter.
	 * @return	The certificate store.
	 */
	ICertificateAuthorityStore getStoreInstance() {
		return connector.getStoreInstance();
	}
	
	/**
	 * Get the next serial number for signing a certificate. The serial number
	 * is incremented as a result of this call.
	 * @return	The next serial number.
	 * @throws CertificateAuthorityException 
	 */
	public long getNextSerialNumber() throws CertificateAuthorityException {
		return connector.getNextSerialNumber();
	}
	
	/**
	 * @return	The object id. 
	 */
	public String getObjectId() {
		return connector.getObjectId();
	}

	/**
	 * Get the self signed root certificate for this CA.
	 * @return	The root certificate.
	 */
	public X509Certificate getCaCertificate() {
		return caCert;
	}

	/**
	 * Get the registration authority certificate for this CA.
	 * @return	The registration authority certificate.
	 */
	public X509Certificate getRaCertificate() {
		return raCert;
	}

	/**
	 * Get the registration authority certificate for this CA.
	 * @return	The registration authority certificate.
	 */
	public PrivateKey getRaKey() {
		return raKey;
	}
	
	/**
	 * Get the CA CRL.
	 * @return	The certificate revocation list. An empty CRL is returned if the
	 * 			CA certificate has not been revoked.
	 */
	public X509CRL getCaCRL() {
		return connector.getCaCRL();
	}
	
	/**
	 * Add the CA CRL for the given date range.
	 * @param	notBefore	The revocation begin date.
	 * @param	notBefore	The revocation end date.
	 * @return	The certificate revocation list.
	 */
	public void addCaCRL(Date notBefore, Date notafter, X509CRL crl) {
		connector.addCaCRL(notBefore, notafter, crl);
	}
	
	/**
	 * @param	cert			The issued certificate for the device.
	 * @param	issuedCertId	The issued certificate id for the device.
	 * @param	caObjectId		The object id of the root certificate authority that signed cert.
	 * @return	The object id of the issued certificate.
	 * @throws	CertificateAuthorityException is the state of the authority is corrupted
	 * @throws	GeneralSecurityException if a certificate error occurs
	 * @throws	IOException if the key store cannot be accessed
	 */
	public void addIssued(String objectId, X509Certificate cert,
							IssuedCertificateIdentifier issuedCertId)
			throws CertificateAuthorityException, GeneralSecurityException, IOException {
		connector.getStoreInstance().addIssued(cert, issuedCertId, objectId, connector.getObjectId());
	}
	
	/**
	 * Revoke the root certificate authority.
	 */
	public void revoke() {
		
	}

	/**
	 * Get the enabled state. The enabled state reflects whether the account is
	 * active or suspended.
	 */
	public boolean isEnabled() {
		return connector.isEnabled();
	}
}