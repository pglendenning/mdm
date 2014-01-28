package com.mdm.scep;

import java.math.BigInteger;
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
public class RootCertificateAuthorityManager {
	// CRL basename for the CA itself
	private static String crlCA = "crl1.lst";
	// CRL basename for all issued certificates
	private static String crlIssued = "crl2.lst";
	// The root certificate store
	private IRootCertificateAuthorityStore store;
	// CA SubjectDN/IssuerDN format
	private String raSubjectDNFormat;
	
	/**
	 * Constructor.
	 * @param store		The data store.
	 */
	public RootCertificateAuthorityManager(IRootCertificateAuthorityStore store) {
		this.store = store;
		raSubjectDNFormat = MdmServiceProperties.getProperty(MdmServiceKey.raX500NameFormatString);
	}
	
	/**
	 * Delete a root certificate authority.
	 * @param	ca	The root certificate authority.
	 * @throws	RootCertificateAuthorityException
	 */
	public void deleteCA(RootCertificateAuthority ca) throws RootCertificateAuthorityException {
		store.deleteCA(ca);
	}

	/**
	 * Get the root certificate authority with the prescribed object id.
	 * @param	objectId	The object id.
	 * @return	A RootCertificateAuthority or null if it does not exist.
	 */
	public RootCertificateAuthority getCA(String objectId) {
		return store.getCA(objectId);
	}
	
	/**
	 * Get the root certificate authority with the prescribed issuer and serial
	 * number.
	 * @param	iasn	The issuer and serial number.
	 * @return	A RootCertificateAuthority or null if it does not exist.
	 */
	public RootCertificateAuthority getCA(IssuerAndSerialNumber iasn) {
		return store.getCA(iasn);
	}
		
	/**
	 * Get the issued certificate with the prescribed issuer and serial number.
	 * @param	iasn	The issuer and serial number.
	 * @return	A RootCertificateAuthorityResult or null if it does not exist.
	 */
	public RootCertificateAuthorityResult getIssued(IssuerAndSerialNumber iasn) {
		return store.getIssued(iasn);
	}

	/**
	 * Get the issued certificate with the prescribed object id.
	 * @param	objectId	The object id.
	 * @return	A RootCertificateAuthorityResult or null if it does not exist.
	 */
	public RootCertificateAuthorityResult getIssued(String objectId) {
		return store.getIssued(objectId);
	}
	
	/**
	 * Get the issued certificate with the prescribed issued certificate identifier.
	 * This is provided for compatibility with the SCEP protocol.
	 * @param	issuedCertId	The issued certificate id.
	 * @return	A RootCertificateAuthorityResult or null if it does not exist.
	 */
	public RootCertificateAuthorityResult getIssued(IssuedCertificateIdentifier issuedCertId) {
		// TODO: add member to IRootCertificateAuthorityStore
		return null;
	}

	/**
	 * Get the next serial number for signing a certificate. The serial number
	 * is incremented as a result of this call.
	 * @return	The next serial number.
	 */
	public long getNextSerialNumber() {
		// We always create the root CA with a serial number of 1
		// We always create the scep RA with a serial number of 2
		long serialNum = store.getNextSerialNumber(); 
		while (serialNum >= 0 && serialNum <= 2)
			serialNum = store.getNextSerialNumber();
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
	 * @return	A RootCertificateAuthority.
	 * @throws	RootCertificateAuthorityException
	 */
	public final RootCertificateAuthority createCA(X509Certificate caCert, PrivateKey caKey, String crlBaseURL, String objectId) throws RootCertificateAuthorityException {
		// verify the CA is self signed and a V3 certificate
		try {
			caCert.verify(caCert.getPublicKey());
			caCert.checkValidity(new Date());
		} catch (Exception e) {
			throw new RootCertificateAuthorityException("Root CA invalid or expired");
		}
		
		// Assume the current serial number is the max value
		if (caCert.getSerialNumber().compareTo(BigInteger.valueOf(Long.MAX_VALUE)) >= 0)
			throw new RootCertificateAuthorityException("Root CA serial number out of bounds");
		
		X509CertificateHolder holder;
		IssuerAndSerialNumber caIasn;
		try {
			holder = new X509CertificateHolder(caCert.getEncoded());
			caIasn = new IssuerAndSerialNumber(holder.getIssuer(), holder.getSerialNumber());
			
		} catch (Exception e) {
			throw new RootCertificateAuthorityException("Root CA invalid");
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
				throw new RootCertificateAuthorityException("Root CA bad organization format");
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
			throw new RootCertificateAuthorityException("Cannot create RA for subject=[" + subjectDN + "]");
		}

		// TODO: Create CA revocation lists - one for each month to expiration

		// Create the root authority
		return store.createCA(caCert, caIasn, raCert, raKeys.getPrivateKey(), true, objectId);
	}
}
