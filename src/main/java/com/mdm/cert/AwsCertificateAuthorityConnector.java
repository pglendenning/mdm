/**
 * 
 */
package com.mdm.cert;

import java.security.cert.X509CRL;
import java.util.Date;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;

/**
 * @author paul
 *
 */
public class AwsCertificateAuthorityConnector implements
		ICertificateAuthorityConnector {

	private String objectId = null;
	private Region region = null;
	private ICertificateAuthorityStore store;
	
	public AwsCertificateAuthorityConnector(String objectId, Region region) {
		this.objectId = objectId;
		this.region = region;
		this.store = getStoreInstance();
	}

	public AwsCertificateAuthorityConnector(String objectId) {
		this(objectId, Region.getRegion(Regions.US_WEST_2));
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getObjectId() {
		return objectId;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addCaCRL(Date notBefore, Date notafter, X509CRL crl) {
		// TODO Auto-generated method stub

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509CRL getCaCRL() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509CRL getIssuedCRL() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setEnabled(boolean enableState) {
		// TODO Auto-generated method stub

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long getNextSerialNumber() throws CertificateAuthorityException {
		return store.getNextSerialNumber(objectId);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ICertificateAuthorityStore getStoreInstance() {
		return new AwsCertificateAuthorityStore(region);
	}

}
