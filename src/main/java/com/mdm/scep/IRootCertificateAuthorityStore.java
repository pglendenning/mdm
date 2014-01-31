package com.mdm.scep;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;

public interface IRootCertificateAuthorityStore {
	
	/**
	 * Create a root certificate authority and add it to the data store. Each entry
	 * in the main store is a Key store with the RA and CA.
	 * 
	 * @param	caCert	The X509 self signed V3 root certificate.
	 * @param	caIasn	The issuer and serial number for the root certificate.
	 * @param	nextSerialNumber	The next available serial number for a signing request.
	 * @param	objectId			An object id to associate with the certificate.
	 * @return	A RootCertificateAuthority.
	 * @throws	RootCertificateAuthorityException is the state of the authority is corrupted
	 * @throws	GeneralSecurityException if a certificate error occurs
	 * @throws	IOException if the key store cannot be accessed
	 */
	public RootCertificateAuthority createCA(X509Certificate caCert, IssuerAndSerialNumber caIasn, 
											 X509Certificate raCert, PrivateKey raKey,
											 boolean enabledState, String objectId) 
			throws RootCertificateAuthorityException, GeneralSecurityException, IOException;

	/**
	 * Delete a root certificate authority form the data store.
	 * @param	ca	The root certificate authority.
	 * @throws	RootCertificateAuthorityException is the state of the authority is corrupted
	 * @throws	GeneralSecurityException if a certificate error occurs
	 * @throws	IOException if the key store cannot be accessed
	 */
	public void deleteCA(RootCertificateAuthority ca) throws RootCertificateAuthorityException, GeneralSecurityException, IOException;
	
	/**
	 * Get the root certificate authority with the prescribed issuer and serial
	 * number.
	 * @param	iasn	The issuer and serial number.
	 * @return	A RootCertificateAuthority.
	 * @throws	RootCertificateAuthorityException is the state of the authority is corrupted
	 * @throws	GeneralSecurityException if a certificate error occurs
	 * @throws	IOException if the key store cannot be accessed
	 */
	public RootCertificateAuthority getCA(IssuerAndSerialNumber iasn) throws GeneralSecurityException, IOException, RootCertificateAuthorityException;
		
	/**
	 * Get the root certificate authority with the prescribed object id.
	 * @param	objectId	The object id
	 * @return	A RootCertificateAuthority.
	 * @throws	GeneralSecurityException if a certificate error occurs
	 * @throws IOException 
	 * @throws RootCertificateAuthorityException 
	 */
	public RootCertificateAuthority getCA(String objectId) throws GeneralSecurityException, IOException, RootCertificateAuthorityException;
		
	/**
	 * Get the issued certificate with the prescribed issuer and serial number.
	 * @param	iasn	The issuer and serial number.
	 * @return	A RootCertificateAuthorityResult or null if it does not exist.
	 */
	public RootCertificateAuthorityResult getIssued(IssuerAndSerialNumber iasn);
	
	/**
	 * Get the issued certificate with the prescribed object id.
	 * @param	objectId	The object id
	 * @return	A RootCertificateAuthorityResult or null if it does not exist.
	 */
	public RootCertificateAuthorityResult getIssued(String objectId);
	
	/**
	 * Get the next serial number for signing a certificate. The serial number
	 * is incremented as a result of this call.
	 * @return	The next serial number.
	 */
	public long getNextSerialNumber();

}
