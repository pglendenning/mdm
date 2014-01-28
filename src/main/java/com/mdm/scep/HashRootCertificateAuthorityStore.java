/**
 * 
 */
package com.mdm.scep;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;

import com.mdm.api.EnrollmentManager;
import com.mdm.api.InvalidObjectIdException;
import com.mdm.utils.X509CertificateGenerator;

/**
 * @author paul
 */
public class HashRootCertificateAuthorityStore implements
		IRootCertificateAuthorityStore {
	
    private static Map<IssuerAndSerialNumber, RootCertificateAuthority> CA_CACHE = null;
    private static Map<String, RootCertificateAuthority> CA_ID_CACHE = null;
    private static Map<IssuerAndSerialNumber, RootCertificateAuthorityResult> ISSUED_CACHE = null;
    private static Map<String, RootCertificateAuthorityResult> ISSUED_ID_CACHE = null;
    private static long serialNumber = 0;
    
    static {
	    CA_CACHE = new HashMap<IssuerAndSerialNumber, RootCertificateAuthority>();
	    CA_ID_CACHE = new HashMap<String, RootCertificateAuthority>();
	    ISSUED_CACHE = new HashMap<IssuerAndSerialNumber, RootCertificateAuthorityResult>();    
	    ISSUED_ID_CACHE = new HashMap<String, RootCertificateAuthorityResult>();
    }
	
	/**
	 * Default constructor
	 */
	public HashRootCertificateAuthorityStore() {
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public RootCertificateAuthority createCA(X509Certificate caCert,
			IssuerAndSerialNumber caIasn, X509Certificate raCert,
			PrivateKey raKey, boolean enabledState, String objectId)
			throws RootCertificateAuthorityException {

		synchronized(HashRootCertificateAuthorityStore.class) {
			if (CA_CACHE.containsKey(caIasn))
				throw new RootCertificateAuthorityException("Duplicate RootCertificateAuthority");
			if (objectId != null && !objectId.isEmpty() && CA_ID_CACHE.containsKey(objectId))
				throw new RootCertificateAuthorityException("Duplicate RootCertificateAuthority objectId");
			RootCertificateAuthority ca = new RootCertificateAuthority();
			ca.setConnector(new HashRootCertificateAuthorityConnector(this, caCert, raCert, raKey, enabledState, objectId));
			CA_CACHE.put(caIasn, ca);
			if (objectId != null && !objectId.isEmpty())
				CA_ID_CACHE.put(objectId, ca);
			return ca;
		}
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public void deleteCA(RootCertificateAuthority ca)
			throws RootCertificateAuthorityException {

		synchronized(HashRootCertificateAuthorityStore.class) {
			IssuerAndSerialNumber caIasn = X509CertificateGenerator.getIssuerAndSerialNumber(ca.getCaCertificate());
			RootCertificateAuthority entry = CA_CACHE.get(caIasn);
			String objectId = null;
			if (entry == null)
				throw new RootCertificateAuthorityException("CA not in cache");
			
			List<IssuerAndSerialNumber> issued = entry.getIssuedList();
			if (issued != null) {
				for (IssuerAndSerialNumber iasn: issued) {
					RootCertificateAuthorityResult result = getIssued(iasn);
					ISSUED_CACHE.remove(iasn);
					if (result != null) {
						try {
							objectId = EnrollmentManager.getObjectIdFromCertifcate(result.getIssuedCertificate());
							if (objectId != null)
								ISSUED_ID_CACHE.remove(objectId);
						} catch (InvalidObjectIdException e) {
						}
					}
				}
			}
			try {
				objectId = EnrollmentManager.getObjectIdFromCertifcate(ca.getCaCertificate());
				if (objectId != null)
					CA_ID_CACHE.remove(objectId);
			} catch (InvalidObjectIdException e) {
			}
			CA_CACHE.remove(caIasn);
		}
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public RootCertificateAuthority getCA(IssuerAndSerialNumber iasn) {
		if (iasn == null) return null;
		synchronized(HashRootCertificateAuthorityStore.class) {
			return CA_CACHE.get(iasn);
		}
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public RootCertificateAuthorityResult getIssued(IssuerAndSerialNumber iasn) {
		if (iasn == null) return null;
		synchronized(HashRootCertificateAuthorityStore.class) {
			return ISSUED_CACHE.get(iasn);
		}
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public RootCertificateAuthority getCA(String objectId) {
		if (objectId == null) return null;
		synchronized(HashRootCertificateAuthorityStore.class) {
			return CA_ID_CACHE.get(objectId);
		}
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public RootCertificateAuthorityResult getIssued(String objectId) {
		if (objectId == null) return null;
		synchronized(HashRootCertificateAuthorityStore.class) {
			return ISSUED_ID_CACHE.get(objectId);
		}
	}
	
    /**
     * {@inheritDoc}
     */
	@Override
	public long getNextSerialNumber() {
		synchronized(HashRootCertificateAuthorityStore.class) {
			return ++serialNumber;
		}
	}
}
