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
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import javax.crypto.Mac;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mdm.auth.PasscodeGenerator;
import com.mdm.auth.TimecodeSigner;
import com.mdm.cert.ICertificateAuthorityStore;
import com.mdm.cert.CertificateAuthority;
import com.mdm.cert.CertificateAuthorityException;
import com.mdm.utils.MdmServiceKey;
import com.mdm.utils.MdmServiceProperties;
import com.mdm.utils.RSAKeyPair;
import com.mdm.utils.X509CertificateGenerator;

public class EnrollmentManager {
	private static final Logger LOG = LoggerFactory.getLogger(EnrollmentManager.class);
	// CRL basename for the CA itself
	private static final String crlCA = "crl1.lst";
	// CRL basename for all issued certificates
	private static final String crlIssued = "crl2.lst";

	private Map<String, EnrollmentHolder> HOLDERS = null;
    private LinkedList<EnrollmentHolder>  HOLDERS_LRU = null;
    
	// Injected from mdmservice.xml property
	private ICertificateAuthorityStore store;
	// Obtained from mdmservice.xml property
	private String crlFormat;
	// RA SubjectDN/IssuerDN format
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
    	HOLDERS = new HashMap<String, EnrollmentHolder>();
		HOLDERS_LRU = new LinkedList<EnrollmentHolder>();
	}
	
	/**
	 * Constructor.
	 * @param	store	The CA store.
	 */
	public EnrollmentManager(ICertificateAuthorityStore store, int intervalPeriod, int validityPeriod) {
		this.store = store;
		crlFormat = MdmServiceProperties.getProperty(MdmServiceKey.crlUrlFormatString);
		raSubjectDNFormat = MdmServiceProperties.getProperty(MdmServiceKey.raX500NameFormatString);
    	HOLDERS = new HashMap<String, EnrollmentHolder>();
		HOLDERS_LRU = new LinkedList<EnrollmentHolder>();
    	INTERVAL_PERIOD = intervalPeriod;
    	VALIDITY_PERIOD = validityPeriod;
	}
	
	/**
	 * Extract the OU part of the subject distinguished name.
	 * @return	The object id.
	 * @throws 	InvalidObjectIdException
	 */
	public static String getObjectIdFromCertifcate(X509Certificate cert) throws InvalidObjectIdException {
		// Get the X500Name and extract the OU part
		X500Name name;
		try {
			name = new JcaX509CertificateHolder(cert).getIssuer();			
		} catch (Exception e) {
			throw new InvalidObjectIdException();
		}
		RDN[] org = name.getRDNs(BCStyle.O);
		if (org.length == 0)
			throw new InvalidObjectIdException();
		return IETFUtils.valueToString(org[0].getFirst().getValue());
	}
	
	/**
	 * Register a parent device.
	 * @param	data	Registration data.
	 * @return	A PKCS12 container encoded as byte array.
	 * @throws CertificateAuthorityException 
	 */
	public byte[] registerParentDevice(RegisterParentRequestData data) throws OperationFailedException {
		// Should have checked in caller
		if (data.isComplete())
			return null;
		
		// Create a new parent identifier
		boolean objExists = false;
		String objectId = null;
		try {
			do {
				objectId = ObjectIdentifier.getInstance();
				CertificateAuthority ca = store.getCA(objectId);
				objExists = ca != null;				
			} while (objExists);
		} catch (Exception e) {
			objExists = false;
		}

		// Create a root V3 certificate for CA and RA
		String issuerDN = String.format("CN=%1$s, L=%2$s, ST=%3$s, C=%4$s, O=%5$s, OU=MDM Authority",
							data.getFriendlyName(), data.getCity(), data.getState(),
							data.getCountry(), objectId);
		String crlBaseURL = String.format(crlFormat, objectId);
		String raSubjectDN = String.format("C=US,L=Woodside,ST=California,O=%1$s,OU=RA,CN=mdm.mdm4all.com",
							data.getFriendlyName());
		//raSubjectDN = String.format(raSubjectDNFormat, O);
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
		X509CertificateHolder holder;
		IssuerAndSerialNumber caIasn;		
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
					
			holder = new X509CertificateHolder(caCert.getEncoded());
			caIasn = new IssuerAndSerialNumber(holder.getIssuer(), holder.getSerialNumber());
			
			// Create the RA certificate and key - serial number == 2
			raKeys.generate();
			raCert = X509CertificateGenerator.createCert(
					raKeys.getPublicKey(),
	        		caCert, caKeys.getPrivateKey(),
	        		2, caCert.getNotAfter(),
	        		raSubjectDN,
	        		crl, null);
			
			// Finally update data store
			CertificateAuthority ca = store.addCA(caCert, caIasn, raCert, raKeys.getPrivateKey(), 10, true, objectId);
			// TODO: Add ca to LRU cache
			
		} catch (Exception e) {
			LOG.info("Failed registerParentDevice({}) with id({}) - {}.({})", issuerDN, objectId, e.getClass().toString(), e.getMessage());
			throw new OperationFailedException();
		}		
		return os.toByteArray();
	}
	
	/**
	 * Unregister the parent device with id equal to objectId
	 * @param	objectId	The parents object identifier.
	 * @return	True if the registration removal was successful.
	 * @throws OperationFailedException 
	 */
	public synchronized void unregisterParentDevice(String objectId) throws OperationFailedException {
		
		try {
			store.removeCA(objectId);
		} catch (CertificateAuthorityException e) {
			LOG.info("Failed unregisterParentDevice(id={}) - {}", objectId, e.getMessage());
			throw new OperationFailedException();
		}
	}
	
	/**
	 * Return a time code signer hashed with the objectId.
	 * @param	objectId	The object id.
	 * @return	A Time code signer using the HmacMd5 algorithm.
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException 
	 * @throws InvalidKeyException 
	 */
	public synchronized TimecodeSigner getTimecodeSigner(String objectId) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
		return new TimecodeSigner(objectId);
	}
	
	@SuppressWarnings("unused")
	public EnrollmentHolder startNewEnrollment(String parentId, String friendlyName) throws OperationFailedException, InvalidObjectIdException {
		// Create a new child identifier
		boolean objExists = false;
		String objectId = null;
		
		String enrollURL = String.format(MdmServiceProperties.getProperty(MdmServiceKey.enrollUrlFormatString), objectId);
		CertificateAuthority ca = null;
		try {
			store.getCA(parentId);
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
		synchronized(this) {
			HOLDERS.put(objectId, holder);
			HOLDERS_LRU.addLast(holder);
		}
		return holder;
	}
	
	/**
	 * Call this from a worker thread at regular intervals.
	 */
	public void cleanUpEnrollments(boolean lowCPU) {
		// Don't keep lock while traversing list
		LinkedList<EnrollmentHolder> holdersToCheck = null;
		synchronized(this) {
			if (HOLDERS_LRU.isEmpty())
				return;
			holdersToCheck = HOLDERS_LRU;
			HOLDERS_LRU = new LinkedList<EnrollmentHolder>();
		}
		
		// Split into two lists
		LinkedList<EnrollmentHolder> holdersToReturn = new LinkedList<EnrollmentHolder>();
		LinkedList<EnrollmentHolder> holdersToRemove = new LinkedList<EnrollmentHolder>();
		while (!holdersToCheck.isEmpty()) {
			EnrollmentHolder holder = holdersToCheck.removeFirst();
			// Reclaim after 2 mins
			if ((holder.isCancelled() || holder.isEnrolled()) && holder.getTimeSinceCompleted() > 120) {
				holdersToRemove.addLast(holder);				
			} else {
				holdersToReturn.addLast(holder);
			}
			
		}
		
		// Remove holders		
		while (!holdersToRemove.isEmpty()) {
			// Sleep for 1 sec every 10 removals if requiring lowCPU
			int i = lowCPU? Integer.MAX_VALUE: 10;
			synchronized(this) {
				while (!holdersToRemove.isEmpty() && i-- > 0) {
					EnrollmentHolder holder = holdersToRemove.removeFirst();
					HOLDERS.remove(holder.getEnrollId());
				}
			}
			
			if (i == 0) {
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					holdersToRemove.addAll(holdersToReturn);
					holdersToReturn = holdersToRemove;
					break;
				}
			}
		}
		
		// Swap holdersToReturn with HOLDERS_LRU
		if (holdersToReturn.isEmpty())
			return;	
		synchronized(this) {
			holdersToReturn.addAll(HOLDERS_LRU);
			HOLDERS_LRU = holdersToReturn;
		}
	}
	
	public synchronized EnrollmentHolder getEnrollment(String enrollId) {
		return HOLDERS.get(enrollId);
	}
	
	public synchronized boolean isValidParentId(String parentId) {
		try {
			store.getCA(parentId);
			return true;
		} catch (CertificateAuthorityException|GeneralSecurityException|IOException e) {
		}
		return false;
	}
}
