package com.mdm.cert;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;

public interface ICertificateAuthorityStore {
	
	/**
	 * Create a root certificate authority and add it to the data store. Each entry
	 * in the main store is a Key store with the RA and CA.
	 * 
	 * @param	caCert		The X509 self signed V3 root certificate.
	 * @param	raCert		The X509 registration certificate.
	 * @param	raKey		The registration private key.
	 * @param	nextSerialNumber	The next available serial number for a signing request.
	 * @param	caObjectId			An object id to associate with the certificate.
	 * @return	A RootCertificateAuthority.
	 * @throws	CertificateAuthorityException is the state of the authority is corrupted
	 * @throws	GeneralSecurityException if a certificate error occurs
	 * @throws	IOException if the key store cannot be accessed
	 */
	public CertificateAuthority addCA(X509Certificate caCert, X509Certificate raCert, 
								PrivateKey raKey, long nextSerialNumber, 
								boolean enabledState, String caObjectId) 
			throws CertificateAuthorityException, GeneralSecurityException, IOException;
	
	/**
	 * Delete a root certificate authority from the data store.
	 * 
	 * @param	caObjectId	The object id of the certificate authority.
	 * @throws	CertificateAuthorityException if the state of the authority is corrupted
	 */
	public void removeCA(String caObjectId)
			throws CertificateAuthorityException;
	
	/**
	 * Get the next serial number for signing a certificate. The serial number
	 * is incremented as a result of this call.
	 * 
	 * @param	caObjectId	The CA object id
	 * @return	The next serial number.
	 * @throws CertificateAuthorityException 
	 */
	public long getNextSerialNumber(String caObjectId) throws CertificateAuthorityException;
	
	/**
	 * Get the root certificate authority with the prescribed issuer and serial
	 * number.
	 * 
	 * @param	iasn	The issuer and serial number.
	 * @return	A RootCertificateAuthority.
	 * @throws	CertificateAuthorityException if the state of the authority is corrupted
	 * @throws	GeneralSecurityException if a certificate error occurs
	 * @throws	IOException if the key store cannot be accessed
	 */
	public CertificateAuthority getCA(IssuerAndSerialNumber iasn)
			throws GeneralSecurityException, IOException, CertificateAuthorityException;
		
	/**
	 * Get the root certificate authority with the prescribed object id.
	 * 
	 * @param	caObjectId	The CA object id
	 * @return	A RootCertificateAuthority.
	 * @throws	GeneralSecurityException if a certificate error occurs
	 * @throws IOException 
	 * @throws CertificateAuthorityException 
	 */
	public CertificateAuthority getCA(String caObjectId)
			throws GeneralSecurityException, IOException, CertificateAuthorityException;

	/**
	 * Get the CA CRL for the given date.
	 * 
	 * @param	caObjectId	The CA object id
	 * @param	date	The revocation date.
	 * @return	The certificate revocation list.
	 */
	public X509CRL getCaCRL(String caObjectId, Date date);
	
	/**
	 * Add the CA CRL for the given date range.
	 * 
	 * @param	caObjectId	The CA object id
	 * @param	notBefore	The revocation begin date.
	 * @param	notBefore	The revocation end date.
	 * @return	The certificate revocation list.
	 */
	public void addCaCRL(String caObjectId, Date notBefore, Date notafter, X509CRL crl);
	
	/**
	 * Get the CA CRL.
	 * 
	 * @param	caObjectId	The CA object id
	 * @return	The certificate revocation list. An empty CRL is returned if the
	 * 			CA certificate has not been revoked.
	 */
	public X509CRL getCaCRL(String caObjectId);
	
	/**
	 * Set the enabled state. The enabled state reflects whether the account is
	 * active or suspended.
	 * 
	 * @param	caObjectId		The CA object id
	 * @param	enabled			The enabled state.
	 */
	public void setCaEnabled(String caObjectId, boolean enabled);
	
	/**
	 * Get the list of all certificate serial numbers issued by this CA
	 * 
	 * @param	caObjectId		The CA object id
	 * @return	The list of issued object id's.
	 */
	public List<String> getIssuedList(String caObjectId);

	/**
	 * Get the Issued CRL.
	 * 
	 * @param	objectId		The issued object id.
	 * @return	The certificate revocation list. An empty CRL is returned is no
	 * 			revocations have occurred.
	 */
	public X509CRL getIssuedCRL(String objectId);
	
	/**
	 * @param	cert			The issued certificate for the device.
	 * @param	issuedCertId	The issued certificate id for the device.
	 * @param	objectId		An object id to associate with the certificate.
	 * @param	caObjectId		The object id of the root certificate authority that signed cert.
	 * @throws	CertificateAuthorityException is the state of the authority is corrupted
	 * @throws	GeneralSecurityException if a certificate error occurs
	 * @throws	IOException if the key store cannot be accessed
	 */
	public void addIssued(X509Certificate cert, IssuedCertificateIdentifier issuedCertId, 
							String objectId, String caObjectId)
			throws CertificateAuthorityException, GeneralSecurityException, IOException;
	
	/**
	 * Remove an issued certificate (device and app).
	 * @param	objectId	The issued object id.
	 */
	public void deleteIssued(String objectId) 
			throws CertificateAuthorityException, GeneralSecurityException, IOException;

	/**
	 * Get the issued certificate with the prescribed issuer and serial number.
	 * @param	iasn	The issuer and serial number.
	 * @return	A RootCertificateAuthorityResult or null if it does not exist.
	 * @throws IOException 
	 * @throws GeneralSecurityException 
	 * @throws CertificateAuthorityException 
	 */
	public IssuedCertificateResult getDeviceIssued(IssuerAndSerialNumber iasn) 
			throws GeneralSecurityException, IOException, CertificateAuthorityException;
	
	/**
	 * Get the issued certificate with the prescribed issued certificate identifier.
	 * @param	issuedCertId	The issued certificate id.
	 * @return	A RootCertificateAuthorityResult or null if it does not exist.
	 * @throws IOException 
	 * @throws GeneralSecurityException 
	 * @throws CertificateAuthorityException 
	 */
	public IssuedCertificateResult getDeviceIssued(IssuedCertificateIdentifier issuedCertId)
			throws GeneralSecurityException, IOException, CertificateAuthorityException;
	
	/**
	 * Get the issued certificate with the prescribed object id.
	 * @param	objectId	The object id
	 * @return	A RootCertificateAuthorityResult or null if it does not exist.
	 * @throws IOException 
	 * @throws GeneralSecurityException 
	 * @throws CertificateAuthorityException 
	 */
	public IssuedCertificateResult getDeviceIssued(String objectId)
			throws GeneralSecurityException, IOException, CertificateAuthorityException;
	
	/**
	 * @param	cert			The issued certificate.
	 * @param	objectId		An object id to associate with the certificate.
	 * @return	A RootCertificateAuthority.
	 * @throws	CertificateAuthorityException is the state of the authority is corrupted
	 * @throws	GeneralSecurityException if a certificate error occurs
	 * @throws	IOException if the key store cannot be accessed
	 */
	public IssuedCertificateResult setAppIssued(X509Certificate cert, String objectId)
			throws CertificateAuthorityException, GeneralSecurityException, IOException;
	
	/**
	 * Get the issued certificate with the prescribed issuer and serial number.
	 * @param	iasn	The issuer and serial number.
	 * @return	A RootCertificateAuthorityResult or null if it does not exist.
	 * @throws IOException 
	 * @throws GeneralSecurityException 
	 * @throws CertificateAuthorityException 
	 */
	public IssuedCertificateResult getAppIssued(IssuerAndSerialNumber iasn) 
			throws GeneralSecurityException, IOException, CertificateAuthorityException;
	
	/**
	 * Get the issued certificate with the prescribed object id.
	 * @param	objectId	The object id
	 * @return	A RootCertificateAuthorityResult or null if it does not exist.
	 * @throws IOException 
	 * @throws GeneralSecurityException 
	 * @throws CertificateAuthorityException 
	 */
	public IssuedCertificateResult getAppIssued(String objectId)
			throws GeneralSecurityException, IOException, CertificateAuthorityException;
	
	
}
