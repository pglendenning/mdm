/**
 * 
 */
package com.mdm.cert;

import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.AmazonClientException;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.simpledb.AmazonSimpleDB;
import com.amazonaws.services.simpledb.AmazonSimpleDBClient;
import com.amazonaws.services.simpledb.model.Attribute;
import com.amazonaws.services.simpledb.model.GetAttributesRequest;
import com.amazonaws.services.simpledb.model.GetAttributesResult;
import com.amazonaws.services.simpledb.model.PutAttributesRequest;
import com.amazonaws.services.simpledb.model.ReplaceableAttribute;
import com.amazonaws.services.simpledb.model.UpdateCondition;
import com.mdm.auth.AwsMdmPropertiesCredentialsProvider;
import com.mdm.utils.MdmServiceKey;
import com.mdm.utils.MdmServiceProperties;

/**
 * @author paul
 *
 */
public class AwsCertificateAuthorityConnector implements
		ICertificateAuthorityConnector {

	private static final Logger LOG = LoggerFactory.getLogger(AwsCertificateAuthorityConnector.class);
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	private AmazonSimpleDB sdb = null;
	private String domainCA = null;		// Simple DB domain for CA
	private String objectId = null;
	private Region region = null;
	
	public AwsCertificateAuthorityConnector(String objectId, Region region) {
		this.sdb = new AmazonSimpleDBClient(new AwsMdmPropertiesCredentialsProvider());
        this.sdb.setRegion(region);
		this.domainCA = MdmServiceProperties.getProperty(MdmServiceKey.awsSimpleDbRootCertificateAuthorityDomain);
		this.objectId = objectId;
		this.region = region;
	}

	public AwsCertificateAuthorityConnector(String objectId) {
		this(objectId, Region.getRegion(Regions.US_WEST_2));
	}
	
	private void verify() throws CertificateAuthorityException {
		if (domainCA == null || objectId == null) {
			throw new CertificateAuthorityException();
		}
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
		verify();
		try {			
			GetAttributesResult result = sdb.getAttributes(new GetAttributesRequest(domainCA, objectId));
			
			String prevcount = null;
            for (Attribute attribute : result.getAttributes()) {
            	if (attribute.getName() == "SerialCounter") {
            		prevcount = attribute.getValue();
            		break;
            	}
            }
            
            if (prevcount == null) {
	        	LOG.error("GetNextSerialNumber(objectId={}) has corrupted db", objectId);
	        	throw new CertificateAuthorityException();
	        }
            
            // Do a conditional put
			Long counter = new Long(prevcount);
    		counter += 1;
			List<ReplaceableAttribute> item = new ArrayList<ReplaceableAttribute>();
	        item.add(new ReplaceableAttribute("SerialCounter", counter.toString(), false));
	        sdb.putAttributes(new PutAttributesRequest(domainCA, objectId, item, new UpdateCondition("SerialCounter", prevcount, true)));
	        return counter-1;
		} catch (AmazonClientException e) {
			LOG.error("GetNextSerialNumber(objectId={}) AWS sdb exception - {}", objectId.toString(), e.getMessage());
        	throw new CertificateAuthorityException(e);			
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ICertificateAuthorityStore getStoreInstance() {
		return new AwsCertificateAuthorityStore(region);
	}

}
