/**
 * 7LL72123648577159
 */
package com.mdm.cert;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mdm.auth.AwsMdmPropertiesCredentialsProvider;
import com.mdm.auth.PasscodeGenerator;
import com.mdm.utils.MdmServiceKey;
import com.mdm.utils.MdmServiceProperties;
import com.mdm.utils.X509CertificateGenerator;
import com.amazonaws.AmazonClientException;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.simpledb.AmazonSimpleDB;
import com.amazonaws.services.simpledb.AmazonSimpleDBClient;
import com.amazonaws.services.simpledb.model.Attribute;
import com.amazonaws.services.simpledb.model.DeleteAttributesRequest;
import com.amazonaws.services.simpledb.model.GetAttributesRequest;
import com.amazonaws.services.simpledb.model.GetAttributesResult;
import com.amazonaws.services.simpledb.model.Item;
import com.amazonaws.services.simpledb.model.PutAttributesRequest;
import com.amazonaws.services.simpledb.model.ReplaceableAttribute;
import com.amazonaws.services.simpledb.model.SelectRequest;
import com.amazonaws.services.simpledb.model.UpdateCondition;

/**
 * @author paul
 *
 */
public class AwsCertificateAuthorityStore implements
		ICertificateAuthorityStore {
	private static final Logger LOG = LoggerFactory.getLogger(AwsCertificateAuthorityStore.class);
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	private AmazonSimpleDB sdb;
	private AmazonS3 s3;
	private String bucketCA;		// s3 bucket for CA's
	private String domainCA;		// Simple DB domain for CA
	private String bucketIssued;	// s3 bucket for issued cert's
	private String domainIssued;	// Simple DB domain for issued cert's
	private String passcode;		
	private PasscodeGenerator auth;
	private Region region;
	
	public AwsCertificateAuthorityStore(Region region) {
		this.sdb = new AmazonSimpleDBClient(new AwsMdmPropertiesCredentialsProvider());
        this.sdb.setRegion(region);
		this.s3 = new AmazonS3Client(new AwsMdmPropertiesCredentialsProvider());
		this.s3.setRegion(region);
		this.domainCA = MdmServiceProperties.getProperty(MdmServiceKey.awsSimpleDbRootCertificateAuthorityDomain);
		this.bucketCA = MdmServiceProperties.getProperty(MdmServiceKey.awsS3RootCertificateAuthorityBucket);
		this.domainIssued = MdmServiceProperties.getProperty(MdmServiceKey.awsSimpleDbIssuedCertificatesDomain);
		this.bucketIssued = MdmServiceProperties.getProperty(MdmServiceKey.awsS3IssuedCertificatesBucket);
		this.region = region;
		
		Mac mac;
		this.auth = null;
		try {
			mac = Mac.getInstance("HmacSHA1");
			String key = MdmServiceProperties.getProperty(MdmServiceKey.pkiAccessKey);
			mac.init(new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA1"));
			this.auth = new PasscodeGenerator(mac);
		} catch (NoSuchAlgorithmException|InvalidKeyException|UnsupportedEncodingException e) {
			LOG.info("Cannot create passcode generator - {}", e.getMessage());
		}
	}

	public AwsCertificateAuthorityStore() {
		this(Region.getRegion(Regions.US_WEST_2));
	}

	private void verify() throws CertificateAuthorityException {
		if (domainCA == null || bucketCA == null || auth == null || passcode == null) {
			throw new CertificateAuthorityException();
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public CertificateAuthority addCA(X509Certificate caCert, IssuerAndSerialNumber caIasn, 
			X509Certificate raCert, PrivateKey raKey, long nextSerialNumber,
			boolean enabledState, String objectId) 
			throws CertificateAuthorityException,
			GeneralSecurityException, IOException {

		verify();
		String blobKey = objectId+"/auth";
		// Add RA cert's to a PKCS12 container and password protect.		
		ByteArrayInputStream fin;
		// FIXME: should specify the character set
		passcode = auth.generateResponseCode(objectId.getBytes());
		ByteArrayOutputStream fOut = new ByteArrayOutputStream();
		Certificate[] chain = new Certificate[2];
		chain[0] = raCert;
		chain[1] = caCert;
		X509CertificateGenerator.savePKCS12(fOut, objectId, passcode, raKey, chain);
		fin = new ByteArrayInputStream(fOut.toByteArray());
		try {
			// Set S3 object metadata and upload object data
			ObjectMetadata metadata = new ObjectMetadata();
			metadata.setCacheControl("no-cache");
			metadata.setContentDisposition(objectId + ".p12");
			metadata.setContentType("application/x-pkcs12");
	        s3.putObject(new PutObjectRequest(bucketCA, blobKey, fin, metadata));
		} catch (AmazonClientException e) {
			LOG.info("CreateCA(objectId={}) AWS s3 exception(1) - {}", objectId, e.getMessage());
			throw new CertificateAuthorityException(e);
		}

		CertificateAuthority ca = null;
		try {
			SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd-HH:mm");
			formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
			String notAfter = formatter.format(caCert.getNotAfter());
			String notBefore = formatter.format(caCert.getNotBefore());

			List<ReplaceableAttribute> item = new ArrayList<ReplaceableAttribute>();
	        item.add(new ReplaceableAttribute("IASN", caIasn.toString(), true));
	        item.add(new ReplaceableAttribute("SerialCounter", new Long(nextSerialNumber).toString(), true));
	        item.add(new ReplaceableAttribute("Enabled", new Boolean(enabledState).toString(), true));
	        item.add(new ReplaceableAttribute("CertNotAfter", notAfter, true));
	        item.add(new ReplaceableAttribute("CertNotBefore", notBefore, true));
	        item.add(new ReplaceableAttribute("Lock", new Boolean(false).toString(), true));
	        sdb.putAttributes(new PutAttributesRequest(domainCA, objectId, item));
			
	        ca = new CertificateAuthority(new AwsCertificateAuthorityConnector(objectId, region), caCert, raCert, raKey);
		} catch (AmazonClientException e) {
			LOG.info("CreateCA(objectId={}) AWS sdb exception(2) - {}", objectId, e.getMessage());
			try {
				// Undo addition
		        s3.deleteObject(bucketCA, blobKey);
			} catch (Exception e2) {
				LOG.info("CreateCA(objectId={}) cannot undo AWS s3 create - {}", objectId, e2.getMessage());			
			}
			throw new CertificateAuthorityException(e);
		}
        return ca;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void removeCA(String objectId)
			throws CertificateAuthorityException {
		
		verify();
		LOG.debug("DeleteCA(objectId={}) initiated", objectId);
		String selectExpression = "select * from `" + domainIssued + "` where ParentId = '" + objectId + "'";
		SelectRequest selectRequest = new SelectRequest(selectExpression);
		try {
			// Get children
			List<String> childIds = new LinkedList<String>();
            for (Item item : sdb.select(selectRequest).getItems()) {
            	childIds.add(item.getName());
            }
            
            // Delete children
            for (String id : childIds) {
    			s3.deleteObject(bucketIssued, id+"/auth/device");
    			s3.deleteObject(bucketIssued, id+"/auth/app");
            	sdb.deleteAttributes(new DeleteAttributesRequest(domainIssued, id));
            }
			
			// Do S3 first else we cannot find objectId from IASN
			s3.deleteObject(bucketCA, objectId+"/auth");
			sdb.deleteAttributes(new DeleteAttributesRequest(domainCA, objectId));
			
		} catch (AmazonClientException e) {
			LOG.error("DeleteCA(objectId{}) AWS s3/sdb exception - {}", objectId, e.getMessage());
			throw new CertificateAuthorityException(e);	
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public CertificateAuthority getCA(IssuerAndSerialNumber iasn)
			throws GeneralSecurityException, IOException,
			CertificateAuthorityException {
		String selectExpression;
		List<Item> items;
		verify();
		selectExpression = "select * from `" + domainCA + "` where IASN = '" + iasn.toString() + "'";
		SelectRequest selectRequest = new SelectRequest(selectExpression);
		try {
			items = sdb.select(selectRequest).getItems();
			if (items.size() == 1) {
				Item item = items.get(0);
				String objectId = item.getName();
		        KeyStore store = KeyStore.getInstance("PKCS12", BC);
				passcode = auth.generateResponseCode(objectId.getBytes());
				
	            S3Object object = s3.getObject(new GetObjectRequest(bucketCA, objectId+"/auth"));		    	
		        store.load(object.getObjectContent(), passcode.toCharArray());
		        // Release AWS resources
		        object.close();
		        
		        Key key = store.getKey(objectId, passcode.toCharArray());    
		        Certificate[] certs = store.getCertificateChain(objectId);
		        if (certs.length == 2) {
			        certs[0].verify(certs[1].getPublicKey());
			        certs[1].verify(certs[1].getPublicKey());
			        CertificateAuthority ca = new CertificateAuthority(
			        					new AwsCertificateAuthorityConnector(objectId, region), 
			        					(X509Certificate)certs[1], 
			        					(X509Certificate)certs[0], (PrivateKey)key);
			        return ca;
		        } else {
		        	LOG.error("GetCA(IASN={}, objectId={}) has corrupted cert store", iasn.toString(), objectId);
		        	throw new CertificateAuthorityException();
		        }
			}
		} catch (AmazonClientException e) {
			LOG.error("GetCA(IASN={}) AWS s3/sdb exception - {}", iasn.toString(), e.getMessage());
        	throw new CertificateAuthorityException(e);			
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public CertificateAuthority getCA(String objectId) 
			throws GeneralSecurityException, IOException,
			CertificateAuthorityException {
		if (objectId == null)
			throw new CertificateAuthorityException();
		
		try {
	        KeyStore store = KeyStore.getInstance("PKCS12", BC);
			passcode = auth.generateResponseCode(objectId.getBytes());
	    	
			S3Object object = s3.getObject(new GetObjectRequest(bucketCA, objectId+"/auth"));			
	        store.load(object.getObjectContent(), passcode.toCharArray());
	        // Release AWS resources
	        object.close();
	        
	        Key key = store.getKey(objectId, passcode.toCharArray());    
	        Certificate[] certs = store.getCertificateChain(objectId);
	        
	        if (certs.length != 2) {
	        	LOG.error("GetCA(objectId={}) has corrupted cert store", objectId);
	        	throw new CertificateAuthorityException();
	        }
	        certs[0].verify(certs[1].getPublicKey());
	        certs[1].verify(certs[1].getPublicKey());
	        CertificateAuthority ca = new CertificateAuthority(
	        					new AwsCertificateAuthorityConnector(objectId, region), 
	        					(X509Certificate)certs[1], 
	        					(X509Certificate)certs[0], (PrivateKey)key);
	        return ca;
		} catch (AmazonClientException e) {
			LOG.error("GetCA(objectId={}) AWS s3/sdb exception - {}", objectId, e.getMessage());
        	throw new CertificateAuthorityException(e);						
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long getNextSerialNumber(String objectId) throws CertificateAuthorityException {
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
     * Displays the contents of the specified input stream as text.
     *
     * @param	is	The input stream to display as text.
     * @throws	IOException
     */
    private static byte[] getBytes(InputStream is) throws IOException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		int nRead;
		byte[] data = new byte[4096];
		
		while ((nRead = is.read(data, 0, data.length)) != -1) {
			buffer.write(data, 0, nRead);
		}
		buffer.flush();
		return buffer.toByteArray();
    }
    
	/**
	 * {@inheritDoc}
	 */
	@Override
	public IssuedCertificateResult getDeviceIssued(IssuerAndSerialNumber iasn)
			throws GeneralSecurityException, IOException,
			CertificateAuthorityException {
		String selectExpression;
		List<Item> items;
		verify();
		selectExpression = "select * from `" + domainIssued + "` where IASN = '" + iasn.toString() + "'";
		SelectRequest selectRequest = new SelectRequest(selectExpression);
		try {
			items = sdb.select(selectRequest).getItems();
			if (items.size() == 1) {
				Item item = items.get(0);
				String objectId = item.getName();
				String parentId = null;
				
                for (Attribute attribute : item.getAttributes()) {
                	if (attribute.getName() == "ParentId") {
                		parentId = attribute.getValue();
                		break;
                	}
                }
                
	            S3Object object = s3.getObject(new GetObjectRequest(bucketIssued, objectId+"/auth/device"));		    	
		        X509Certificate cert = new JcaX509CertificateConverter().
		        		getCertificate(new X509CertificateHolder(getBytes(object.getObjectContent())));
		    
		        // Release AWS resources
		        object.close();
                
                // Will throw an exception if parentId is null
                CertificateAuthority ca = getCA(parentId);
                return new IssuedCertificateResult(ca, cert, objectId);
			}
		} catch (AmazonClientException e) {
			LOG.error("GetCA(IASN={}) AWS s3/sdb exception - {}", iasn.toString(), e.getMessage());
        	throw new CertificateAuthorityException(e);			
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IssuedCertificateResult getDeviceIssued(String objectId)
			throws GeneralSecurityException, IOException,
			CertificateAuthorityException {
		verify();
		try {
			
			GetAttributesResult result = sdb.getAttributes(new GetAttributesRequest(domainIssued, objectId));
			
			String parentId = null;
            for (Attribute attribute : result.getAttributes()) {
            	if (attribute.getName() == "ParentId") {
            		parentId = attribute.getValue();
            		break;
            	}
            }
                
            S3Object object = s3.getObject(new GetObjectRequest(bucketIssued, objectId+"/auth/device"));		    	
	        X509Certificate cert = new JcaX509CertificateConverter().
	        		getCertificate(new X509CertificateHolder(getBytes(object.getObjectContent())));
		    
	        // Release AWS resources
	        object.close();
                
            // Will throw an exception if parentId is null
            CertificateAuthority ca = getCA(parentId);
            return new IssuedCertificateResult(ca, cert, objectId);
		} catch (AmazonClientException e) {
			LOG.error("GetCA(objectId={}) AWS s3/sdb exception - {}", objectId.toString(), e.getMessage());
        	throw new CertificateAuthorityException(e);			
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IssuedCertificateResult getDeviceIssued(IssuedCertificateIdentifier issuedCertId)
			throws GeneralSecurityException, IOException,
			CertificateAuthorityException {
		String selectExpression;
		List<Item> items;
		verify();
		selectExpression = "select * from `" + domainIssued + "` where ICID = '" + issuedCertId.toString() + "'";
		SelectRequest selectRequest = new SelectRequest(selectExpression);
		try {
			items = sdb.select(selectRequest).getItems();
			if (items.size() == 1) {
				Item item = items.get(0);
				String objectId = item.getName();
				String parentId = null;
				
                for (Attribute attribute : item.getAttributes()) {
                	if (attribute.getName() == "ParentId") {
                		parentId = attribute.getValue();
                		break;
                	}
                }
                
	            S3Object object = s3.getObject(new GetObjectRequest(bucketIssued, objectId+"/auth/device"));		    	
		        X509Certificate cert = new JcaX509CertificateConverter().
		        		getCertificate(new X509CertificateHolder(getBytes(object.getObjectContent())));
		    
		        // Release AWS resources
		        object.close();
                
                // Will throw an exception if parentId is null
                CertificateAuthority ca = getCA(parentId);
                return new IssuedCertificateResult(ca, cert, objectId);
			}
		} catch (AmazonClientException e) {
			LOG.error("GetCA(ICID={}) AWS s3/sdb exception - {}", issuedCertId.toString(), e.getMessage());
        	throw new CertificateAuthorityException(e);			
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addIssued(X509Certificate cert,
			IssuerAndSerialNumber iasn,
			IssuedCertificateIdentifier issuedCertId, String objectId,
			String parentId) throws CertificateAuthorityException,
			GeneralSecurityException, IOException {
        
		verify();
		String blobKey = objectId+"/auth/device";
		ByteArrayInputStream fin;
		fin = new ByteArrayInputStream(cert.getEncoded());
		try {
			// Set S3 object metadata and upload object data
			ObjectMetadata metadata = new ObjectMetadata();
			metadata.setCacheControl("no-cache");
			metadata.setContentDisposition(objectId + "_device.crt");
			metadata.setContentType("application/x-x509-ca-cert");
	        s3.putObject(new PutObjectRequest(bucketIssued, blobKey, fin, metadata));
		} catch (AmazonClientException e) {
			LOG.info("putIssued(objectId={}) AWS s3 exception(1) - {}", objectId, e.getMessage());
			throw new CertificateAuthorityException(e);
		}

		try {
			List<ReplaceableAttribute> item = new ArrayList<ReplaceableAttribute>();
	        item.add(new ReplaceableAttribute("IASN", iasn.toString(), true));
	        if (issuedCertId != null)
		        item.add(new ReplaceableAttribute("ICID", issuedCertId.toString(), true));
	        else
		        item.add(new ReplaceableAttribute("ICID", "null", true));
	        item.add(new ReplaceableAttribute("ParentId", parentId, true));
	        sdb.putAttributes(new PutAttributesRequest(domainIssued, objectId, item));
		} catch (AmazonClientException e) {
			LOG.info("putIssued(objectId={}) AWS sdb exception(2) - {}", objectId, e.getMessage());
			try {
				// Undo addition
		        s3.deleteObject(bucketIssued, blobKey);
			} catch (Exception e2) {
				LOG.info("putIssued(objectId={}) cannot undo AWS s3 create - {}", objectId, e2.getMessage());			
			}
			throw new CertificateAuthorityException(e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void deleteIssued(String objectId)
			throws CertificateAuthorityException, GeneralSecurityException, IOException {
		
		verify();
		
		// Now delete item
		LOG.debug("DeleteIssued(objectId={}) initiated", objectId);
		try {
			// Do S3 first else we cannot find objectId from IASN
			s3.deleteObject(bucketIssued, objectId+"/auth/app");
			s3.deleteObject(bucketIssued, objectId+"/auth/device");
			sdb.deleteAttributes(new DeleteAttributesRequest(domainIssued, objectId));
		} catch (AmazonClientException e) {
			LOG.error("DeleteIssued(objectId{}) AWS s3/sdb exception - {}", objectId, e.getMessage());
			throw new CertificateAuthorityException(e);	
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IssuedCertificateResult setAppIssued(X509Certificate cert, String objectId)
			throws CertificateAuthorityException, GeneralSecurityException, IOException {
		
		// Must always add the device issued first
		IssuedCertificateResult device = getDeviceIssued(objectId);
		if (device == null)
			return null;
		
		String blobKey = objectId+"/auth/app";
		ByteArrayInputStream fin;
		fin = new ByteArrayInputStream(cert.getEncoded());
		try {
			// Set S3 object metadata and upload object data
			ObjectMetadata metadata = new ObjectMetadata();
			metadata.setCacheControl("no-cache");
			metadata.setContentDisposition(objectId + "_app.crt");
			metadata.setContentType("application/x-x509-ca-cert");			
	        s3.putObject(new PutObjectRequest(bucketIssued, blobKey, fin, metadata));
	        
	        return new IssuedCertificateResult(device.getCa(), cert, objectId);
		} catch (AmazonClientException e) {
			LOG.error("SetAppIssued(objectId={}) AWS s3 exception(1) - {}", objectId, e.getMessage());
			throw new CertificateAuthorityException(e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509CRL getCaCRL(String caObjectId, Date date) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addCaCRL(String caObjectId, Date notBefore, Date notafter,
			X509CRL crl) {
		// TODO Auto-generated method stub
		
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509CRL getCaCRL(String caObjectId) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setCaEnabled(String caObjectId, boolean enabled) {
		// TODO Auto-generated method stub
		
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<String> getIssuedList(String caObjectId) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509CRL getIssuedCRL(String objectId) {
		// TODO Auto-generated method stub
		return null;
	}
}
