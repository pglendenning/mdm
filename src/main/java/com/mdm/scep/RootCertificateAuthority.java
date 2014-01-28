package com.mdm.scep;

import static org.junit.Assert.fail;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;

import com.mdm.api.EnrollmentManager;

/**
 * The RootCertificateAutority is used by SCEP to manage certificates associated with
 * each account. For family MDM  the root will be the parents certificate identify.
 * @author paul
 */
public class RootCertificateAuthority {
	private IRootCertificateAuthorityConnector connector;
	private X509Certificate caCACHE;
	private X509Certificate raCACHE;
	
	/**
	 * Set the connector.
	 * @param	conn	The connector.
	 */
	public void setConnector(IRootCertificateAuthorityConnector conn) {
		connector = conn;
	}
	
	/**
	 * Get the connector
	 * @return	The connector.
	 */
	IRootCertificateAuthorityConnector getConnector() {
		return connector;
	}
	
	/**
	 * Get the next serial number for signing a certificate. The serial number
	 * is incremented as a result of this call.
	 * @return	The next serial number.
	 */
	public long getNextSerialNumber() {
		return connector.getStore().getNextSerialNumber();
	}
	
	/**
	 * Get the self signed root certificate for this CA.
	 * @return	The root certificate.
	 */
	public X509Certificate getCaCertificate() {
		if (caCACHE == null)
			caCACHE = connector.getCaCertificate();
		return caCACHE;
	}

	/**
	 * Get the registration authority certificate for this CA.
	 * @return	The registration authority certificate.
	 */
	public X509Certificate getRaCertificate() {
		if (raCACHE == null)
			raCACHE = connector.getCaCertificate();
		return raCACHE;
	}

	/**
	 * Get the registration authority certificate for this CA.
	 * @return	The registration authority certificate.
	 */
	public X509Certificate getRaKey() {
		if (raCACHE == null)
			raCACHE = connector.getCaCertificate();
		return raCACHE;
	}
	
	/**
	 * Get all certificates issued by this authority
	 * @return
	 */
	public List<IssuerAndSerialNumber> getIssuedList() {
		return connector.getIssuedList();
	}
	
	/**
	 * Add another issued certificate.
	 * @throws RootCertificateAuthorityException 
	 */
	public void addIssued(String objectId, X509Certificate issuedCert) throws RootCertificateAuthorityException {
		// Verify we are the issuer
       try {
    	   issuedCert.verify(getCaCertificate().getPublicKey());
        } catch (Exception e) {
        	throw new RootCertificateAuthorityException(e.getMessage());
        }
	 
		// TODO: add method to IRootCertificateAuthorityConnector
	}
	
	/**
	 * Get the CA CRL for the given date. A CRL for each month is generated
	 * 			automatically when the CA is created.
	 * @param	date	The revocation date.
	 * @return	The certificate revocation list.
	 */
	public X509CRL getCaCRL(Date date) {
		return connector.getCaCRL(date);
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
	 * Get the CA CRL.
	 * @return	The certificate revocation list. An empty CRL is returned if the
	 * 			CA certificate has not been revoked.
	 */
	public X509CRL getCaCRL() {
		return connector.getCaCRL();
	}
	
	/**
	 * Get the Issued CRL.
	 * @return	The certificate revocation list. An empty CRL is returned is no
	 * 			revocations have occurred.
	 */
	public X509CRL getIssuedCRL() {
		return connector.getIssuedCRL();
	}
	
	/**
	 * Revoke the root certificate authority.
	 */
	public void revoke() {
		
	}

	/**
	 * Revoke an issued certificate.
	 */
	public void revokeIssued(X509Certificate cert) {
		
	}
	
	/**
	 * Set the enabled state. The enabled state reflects whether the account is
	 * active or suspended.
	 * @param	enableState		The enabled state.
	 */
	public void setEnabled(boolean enableState) {
		connector.setEnabled(enableState);
	}
	
	/**
	 * Get the enabled state. The enabled state reflects whether the account is
	 * active or suspended.
	 */
	public boolean isEnabled() {
		return connector.isEnabled();
	}
}