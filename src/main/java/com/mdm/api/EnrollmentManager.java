package com.mdm.api;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mdm.auth.PasscodeGenerator;
import com.mdm.auth.TimecodeSigner;
import com.mdm.cert.ICertificateAuthorityStore;
import com.mdm.cert.CertificateAuthority;
import com.mdm.cert.CertificateAuthorityException;
import com.mdm.cert.RSAKeyPair;
import com.mdm.cert.X509CertificateGenerator;
import com.mdm.utils.MdmServiceKey;
import com.mdm.utils.MdmServiceProperties;
import com.mdm.utils.ObjectCache;
import com.mdm.utils.ObjectIdentifier;

/**
 * 
 * This class is thread safe.
 * @author paul
 *
 */
public class EnrollmentManager {
	private static final Logger LOG = LoggerFactory.getLogger(EnrollmentManager.class);
	// CRL basename for the CA itself
	private static final String crlCA = "crl1.lst";
	// CRL basename for all issued certificates
	private static final String crlIssued = "crl2.lst";

	private ObjectCache<EnrollmentHolder> HOLDERS = null;
    
	// Injected from mdmservice.xml property
	private ICertificateAuthorityStore store;
	// Obtained from mdmservice.xml property
	private String crlFormat;
	// RA SubjectDN/IssuerDN format
	@SuppressWarnings("unused")
	private String raSubjectDNFormat;
	// Default validity window (in seconds) for the timecode. The timecode is
	// valid for the current time +/- VALIDITY_PERIOD.
	private int VALIDITY_PERIOD = 20;
	// Default time code update interval period in seconds. 
	private int INTERVAL_PERIOD = 60;
	
	/**
	 * Constructor.
	 * @param	store	The CA store.
	 */
	public EnrollmentManager(ICertificateAuthorityStore store) {
		this.store = store;
		crlFormat = MdmServiceProperties.getProperty(MdmServiceKey.crlUrlFormatString);
		raSubjectDNFormat = MdmServiceProperties.getProperty(MdmServiceKey.raX500NameFormatString);
    	HOLDERS = new ObjectCache<EnrollmentHolder>();
	}
	
	/**
	 * Constructor.
	 * @param	store	The CA store.
	 */
	public EnrollmentManager(ICertificateAuthorityStore store, int intervalPeriod, int validityPeriod) {
		this.store = store;
		crlFormat = MdmServiceProperties.getProperty(MdmServiceKey.crlUrlFormatString);
		raSubjectDNFormat = MdmServiceProperties.getProperty(MdmServiceKey.raX500NameFormatString);
    	HOLDERS = new ObjectCache<EnrollmentHolder>();
    	INTERVAL_PERIOD = intervalPeriod;
    	VALIDITY_PERIOD = validityPeriod;
	}
	
	/**
	 * Check the hash of the organization and objectId. The Md5 hash of this value
	 * must equal the common name.
	 * @return	True if the certificate is valid.
	 * @throws 	InvalidObjectIdException
	 */
	public static boolean validateCertifcate(String objectId, X509Certificate cert) throws InvalidObjectIdException {
		X500Name name;
		try {
			name = new JcaX509CertificateHolder(cert).getIssuer();			
		} catch (Exception e) {
			throw new InvalidObjectIdException();
		}
		RDN[] cn = name.getRDNs(BCStyle.CN);
		RDN[] org = name.getRDNs(BCStyle.O);
		if (cn.length == 0 || org.length == 0)
			throw new InvalidObjectIdException();
		String hash = IETFUtils.valueToString(cn[0].getFirst().getValue());
		String friendlyName = IETFUtils.valueToString(org[0].getFirst().getValue());
		
		try {
			Mac mac = Mac.getInstance("HmacMD5");
			mac.init(new SecretKeySpec(objectId.getBytes("UTF-8"), "HmacMD5"));
			return hash.equals(new BigInteger(mac.doFinal(friendlyName.getBytes())).toString(32));
		} catch (Exception e) {
			throw new InvalidObjectIdException(e);
		}
	}
	
	/**
	 * Register a parent device.
	 * @param	data	Registration data.
	 * @return	A PKCS12 container encoded as byte array.
	 * @throws CertificateAuthorityException 
	 */
	public RegisterParentResponseData registerParentDevice(RegisterParentRequestData data) throws OperationFailedException {
		// Should have checked in caller
		if (!data.isComplete())
			throw new OperationFailedException();
		
		// Create a new parent identifier
		boolean objExists = false;
		String objectId = null;
		CertificateAuthority ca = null;
		try {
			do {
				objectId = ObjectIdentifier.getInstance();
				synchronized(store) {
					ca = store.getCA(objectId);
					objExists = ca != null;	
				}
			} while (objExists);
		} catch (Exception e) {
			objExists = false;
		}

		// Create a root V3 certificate for CA and RA
		
		// Create a unique common name but don't expose object key. This
		// ensures the issuer name is unique.
		String cn = null;
		try {
			Mac mac = Mac.getInstance("HmacMD5");
			mac.init(new SecretKeySpec(objectId.getBytes("UTF-8"), "HmacMD5"));
			cn = new BigInteger(mac.doFinal(data.getFriendlyName().getBytes())).toString(32);
		} catch (Exception e) {
			throw new OperationFailedException(e);
		}
		
		String issuerDN = String.format("CN=%1$s, L=%2$s, ST=%3$s, C=%4$s, O=%5$s, OU=MDM Authority",
							cn, data.getCity(), data.getState(),
							data.getCountry(), data.getFriendlyName());
		String crlBaseURL = String.format(crlFormat, objectId);
		String raSubjectDN = String.format("C=US,L=Woodside,ST=California,O=%1$s,OU=RA,CN=mdm.mdm4all.com",
							data.getFriendlyName());
		// raSubjectDN = String.format(raSubjectDNFormat, O);
		// Create CRL links
		StringBuffer x = new StringBuffer();
		x.append(crlBaseURL);
		x.append(crlCA);
		x.append(",");
		x.append(crlBaseURL);
		x.append(crlIssued);
		String crl = x.toString();
				
		X509Certificate caCert;
		RSAKeyPair caKeys = new RSAKeyPair();
		X509Certificate raCert;
		RSAKeyPair raKeys = new RSAKeyPair();
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		try {
			Certificate[] chain = new Certificate[1];
			caKeys.generate();
			// Always create root certificates with a serial number of 1 and a 1 year subscription
			caCert = X509CertificateGenerator.createV3RootCA(caKeys.getPublicKey(), caKeys.getPrivateKey(), 
								1, 365, issuerDN, null, null);

			// Create PKCS12 container
			chain[0] = caCert;		
			X509CertificateGenerator.savePKCS12(os, data.getFriendlyName(), data.getUserId(), caKeys.getPrivateKey(), chain);
					
			// Create the RA certificate and key - serial number == 2
			raKeys.generate();
			raCert = X509CertificateGenerator.createCert(
					raKeys.getPublicKey(),
	        		caCert, caKeys.getPrivateKey(),
	        		2, caCert.getNotAfter(),
	        		raSubjectDN,
	        		crl, null);
			
			// Finally update data store
			synchronized(store) {
				ca = store.addCA(caCert, raCert, raKeys.getPrivateKey(), 10, true, objectId);
			}
			// TODO: Add ca to LRU cache
			
		} catch (Exception e) {
			LOG.info("Failed registerParentDevice({}) with id({}) - {}.({})", issuerDN, objectId, e.getClass().toString(), e.getMessage());
			throw new OperationFailedException();
		}		
		return new RegisterParentResponseData(objectId, os.toByteArray());
	}
	
	/**
	 * Unregister the parent device with id equal to objectId
	 * @param	objectId	The parents object identifier.
	 * @return	True if the registration removal was successful.
	 * @throws OperationFailedException 
	 */
	public void unregisterParentDevice(String objectId) throws OperationFailedException {
		
		try {
			synchronized(store) {
				store.removeCA(objectId);
			}
		} catch (CertificateAuthorityException e) {
			LOG.info("Failed unregisterParentDevice(id={}) - {}", objectId, e.getMessage());
			throw new OperationFailedException();
		}
	}
	
	/**
	 * Return a time code signer hashed with the objectId.
	 * @param	objectId	The object id.
	 * @return	A Time code signer using the HmacSHA1 algorithm.
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException 
	 * @throws InvalidKeyException 
	 */
	public static TimecodeSigner getTimecodeSigner(String objectId) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
		return new TimecodeSigner(objectId);
	}
	
	public EnrollmentHolder startNewEnrollment(String parentId, String friendlyName) throws OperationFailedException, InvalidObjectIdException {
		// Create a new child identifier
		boolean objExists = false;
		String objectId = null;
		
		String enrollURL = String.format(MdmServiceProperties.getProperty(MdmServiceKey.enrollUrlFormatString), objectId);
		CertificateAuthority ca = null;
		try {
			synchronized(store) {
				ca = store.getCA(parentId);
			}
		} catch (CertificateAuthorityException|GeneralSecurityException|IOException e) {
			throw new InvalidObjectIdException();
		}

		if (ca == null) {
			LOG.warn("Failed startNewEnrollment(parentId={}, name={}) - CertificateAuthority == null", parentId, friendlyName);
			throw new OperationFailedException();
		}
				
		do {
			objectId = ObjectIdentifier.getInstance();
			
			// TODO: query data-store to see if object exists
			//objExists = null != store.getCA(objectId) || null != certManager.getIssued(objectId);
			
		} while (objExists);
		
		long serialNum1 = 0;
		long serialNum2 = 0;
		EnrollmentHolder holder = null;
		try {
			serialNum1 = ca.getNextSerialNumber();
			serialNum2 = ca.getNextSerialNumber();
			
			PasscodeGenerator gen = new PasscodeGenerator(getTimecodeSigner(parentId), -1, INTERVAL_PERIOD, VALIDITY_PERIOD);
			holder = new EnrollmentHolder(parentId, ca, objectId, serialNum1, serialNum2, enrollURL, gen);
		} catch(CertificateAuthorityException | NoSuchAlgorithmException | InvalidKeyException | UnsupportedEncodingException e) {
			LOG.warn("Failed startNewEnrollment(parentId={}, name={}) - {}", parentId, friendlyName, e.getMessage());
			throw new OperationFailedException();
		}
		// TODO: need a better persistence model that scales
		// ObjectCache is thread safe
		HOLDERS.putObject(objectId, holder);
		return holder;
	}
	
	/**
	 * Call this from a worker thread at regular intervals.
	 */
	public void cleanUpEnrollments(boolean lowCPU) {
		// ObjectCache is thread safe
		ObjectCache<EnrollmentHolder> holdersToCheck = new ObjectCache<EnrollmentHolder>();
		holdersToCheck.transferCache(HOLDERS);
		
		LinkedList<EnrollmentHolder> holdersToReturn = new LinkedList<EnrollmentHolder>();
		while (!holdersToCheck.isEmpty()) {
			EnrollmentHolder holder = holdersToCheck.removeLRU();
			// Reclaim after 2 mins
			if (!(holder.isCancelled() || holder.isEnrolled()) || holder.getTimeSinceCompleted() <= 120) {
				holdersToReturn.addFirst(holder);
			}
			
		}
		
		// Return holders - acquire lock outside loop
		do {
			int i = (lowCPU)? 100: Integer.MAX_VALUE;
			synchronized(HOLDERS) {
				while (!holdersToReturn.isEmpty() && --i != 0) {
					EnrollmentHolder holder = holdersToReturn.removeFirst();
					HOLDERS.putObjectLRU(holder.getEnrollId(), holder);
				}
			}
			if (i == 0) {
				// Sleep
			}
		} while (!holdersToReturn.isEmpty());
	}
	
	public EnrollmentHolder getEnrollment(String enrollId) {
		// ObjectCache is thread safe
		return HOLDERS.getObject(enrollId);
	}
	
	public boolean isValidParentId(String parentId) {
		try {
			synchronized(store) {
				store.getCA(parentId);
			}
			return true;
		} catch (CertificateAuthorityException|GeneralSecurityException|IOException e) {
		}
		return false;
	}
}
