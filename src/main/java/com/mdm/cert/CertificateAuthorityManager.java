package com.mdm.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cert.X509CertificateHolder;

import com.mdm.utils.MdmServiceKey;
import com.mdm.utils.MdmServiceProperties;
import com.mdm.utils.RSAKeyPair;
import com.mdm.utils.X509CertificateGenerator;

/**
 * Class to manage creation and deletion of certificate authorities.
 * Each CA has an RA for the SCEP side.
 * 
 * @author paul
 */
public class CertificateAuthorityManager {
	// CRL basename for the CA itself
	private static String crlCA = "crl1.lst";
	// CRL basename for all issued certificates
	private static String crlIssued = "crl2.lst";
	// The root certificate store
	private ICertificateAuthorityStore store;
	// CA SubjectDN/IssuerDN format
	private String raSubjectDNFormat;
	
	/**
	 * Constructor.
	 * @param store		The data store.
	 */
	public CertificateAuthorityManager(ICertificateAuthorityStore store) {
		this.store = store;
		raSubjectDNFormat = MdmServiceProperties.getProperty(MdmServiceKey.raX500NameFormatString);
	}
	
	/**
	 * Delete a root certificate authority.
	 * @param	ca	The root certificate authority.
	 * @throws	CertificateAuthorityException
	 */
	public void deleteCA(CertificateAuthority ca)
			throws CertificateAuthorityException {
		store.deleteCA(ca.getObjectId());
	}

	/**
	 * Get the root certificate authority with the prescribed object id.
	 * @param	objectId	The object id.
	 * @return	A CertificateAuthority or null if it does not exist.
	 */
	public CertificateAuthority getCA(String objectId)
			throws CertificateAuthorityException {
		try {
			return store.getCA(objectId);
		} catch (GeneralSecurityException | IOException e) {
			throw new CertificateAuthorityException(e);
		}
	}
	
	/**
	 * Get the root certificate authority with the prescribed issuer and serial
	 * number.
	 * @param	iasn	The issuer and serial number.
	 * @return	A CertificateAuthority or null if it does not exist.
	 */
	public CertificateAuthority getCA(IssuerAndSerialNumber iasn)
			throws CertificateAuthorityException {
		try {
			return store.getCA(iasn);
		} catch (GeneralSecurityException | IOException e) {
			throw new CertificateAuthorityException(e);
		}
	}
		
	/**
	 * Get the issued certificate with the prescribed issuer and serial number.
	 * @param	iasn	The issuer and serial number.
	 * @return	A CertificateAuthorityResult or null if it does not exist.
	 * @throws CertificateAuthorityException 
	 */
	public IssuedCertificateResult getDeviceIssued(IssuerAndSerialNumber iasn)
			throws CertificateAuthorityException {
		try {
			return store.getDeviceIssued(iasn);
		} catch (GeneralSecurityException | IOException e) {
			throw new CertificateAuthorityException(e);
		}
	}

	/**
	 * Get the issued certificate with the prescribed object id.
	 * @param	objectId	The object id.
	 * @return	A CertificateAuthorityResult or null if it does not exist.
	 * @throws CertificateAuthorityException 
	 * @throws IOException 
	 * @throws GeneralSecurityException 
	 */
	public IssuedCertificateResult getDeviceIssued(String objectId)
			throws CertificateAuthorityException {
		try {
			return store.getDeviceIssued(objectId);
		} catch (GeneralSecurityException | IOException e) {
			throw new CertificateAuthorityException(e);
		}
	}
	
	/**
	 * Get the issued certificate with the prescribed issued certificate identifier.
	 * This is provided for compatibility with the SCEP protocol.
	 * @param	issuedCertId	The issued certificate id.
	 * @return	A CertificateAuthorityResult or null if it does not exist.
	 * @throws CertificateAuthorityException 
	 */
	public IssuedCertificateResult getDeviceIssued(IssuedCertificateIdentifier issuedCertId) 
			throws CertificateAuthorityException {
		try {
			return store.getDeviceIssued(issuedCertId);
		} catch (GeneralSecurityException | IOException e) {
			throw new CertificateAuthorityException(e);
		}
	}

	/**
	 * Get the next serial number for signing a certificate. The serial number
	 * is incremented as a result of this call.
	 * @return	The next serial number.
	 * @throws CertificateAuthorityException 
	 */
	public long getNextSerialNumber(String objectId)
			throws CertificateAuthorityException {
		// We always create the root CA with a serial number of 1
		// We always create the scep RA with a serial number of 2
		long serialNum = store.getNextSerialNumber(objectId); 
		while (serialNum >= 0 && serialNum <= 2)
			serialNum = store.getNextSerialNumber(objectId);
		return serialNum;
	}
	
	/**
	 * Create a root certificate authority.
	 * @param	caCert		The X509 self signed V3 root certificate.
	 * @param	caKey		The private key.
	 * @param	crlBaseURL	The url to the certification revocation list. The
	 * 			URL must be a directory on the MDM website. This directory will
	 * 			contain two CRL's: crl1.lst the CA crl, and crl2.lst for all
	 * 			issued certificates. Set to null if no CRL.
	 * @param	objectId	The object id.
	 * @return	A CertificateAuthority.
	 * @throws	CertificateAuthorityException
	 */
	public final CertificateAuthority createCA(X509Certificate caCert, 
			PrivateKey caKey, String crlBaseURL, String objectId) 
			throws CertificateAuthorityException {
		// verify the CA is self signed and a V3 certificate
		try {
			caCert.verify(caCert.getPublicKey());
			caCert.checkValidity(new Date());
		} catch (Exception e) {
			throw new CertificateAuthorityException("Root CA invalid or expired");
		}
		
		// Assume the current serial number is the max value
		if (caCert.getSerialNumber().compareTo(BigInteger.valueOf(Long.MAX_VALUE)) >= 0)
			throw new CertificateAuthorityException("Root CA serial number out of bounds");
		
		X509CertificateHolder holder;
		IssuerAndSerialNumber caIasn;
		try {
			holder = new X509CertificateHolder(caCert.getEncoded());
			caIasn = new IssuerAndSerialNumber(holder.getIssuer(), holder.getSerialNumber());
			
		} catch (Exception e) {
			throw new CertificateAuthorityException("Root CA invalid");
		}
		
		// Create a registration authority for this certificate
		X509Certificate raCert;
		RSAKeyPair raKeys = new RSAKeyPair();
		String subjectDN = "";
		try {
			// Create RA subject DN
			// RA has same organization but OU=RA
			String crl = null;
			String subject = caCert.getSubjectX500Principal().toString();
			int s = subject.indexOf("O=");
			String O = subject.substring(s, subject.indexOf(',', s));
			if (O.isEmpty() || O.contains(","))
				throw new CertificateAuthorityException("Root CA bad organization format");
			subjectDN = String.format(raSubjectDNFormat, O);
			
			// Create CRL links
			if (crlBaseURL != null) {
				StringBuffer x = new StringBuffer();
				x.append(crlBaseURL);
				x.append(crlCA);
				x.append(",");
				x.append(crlBaseURL);
				x.append(crlIssued);
				crl = x.toString();
			}
			
			// Create the RA certificate and key - serial number == 2
			raKeys.generate();
			raCert = X509CertificateGenerator.createCert(
					raKeys.getPublicKey(),
	        		caCert, caKey,
	        		2, caCert.getNotAfter(),
	        		subjectDN,
	        		crl, null);
			
		} catch (Exception e) {
			throw new CertificateAuthorityException("Cannot create RA for subject=[" + subjectDN + "]");
		}

		// Create the root authority
		try {
			return store.createCA(caCert, caIasn, raCert, raKeys.getPrivateKey(), 10, true, objectId);
		} catch (GeneralSecurityException | IOException e) {
			throw new CertificateAuthorityException(e);
		}
	}
}
