/**
 * 
 */
package com.mdm.scep;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mdm.auth.AwsMdmPropertiesCredentialsProvider;
import com.mdm.auth.PasscodeGenerator;
import com.mdm.utils.MdmServiceKey;
import com.mdm.utils.MdmServiceProperties;
import com.mdm.utils.X509CertificateGenerator;

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
import com.amazonaws.services.simpledb.model.DeleteAttributesRequest;
import com.amazonaws.services.simpledb.model.Item;
import com.amazonaws.services.simpledb.model.PutAttributesRequest;
import com.amazonaws.services.simpledb.model.ReplaceableAttribute;
import com.amazonaws.services.simpledb.model.SelectRequest;

/**
 * @author paul
 *
 */
public class AwsSimpleDbRootCertificateAuthorityStore implements
		IRootCertificateAuthorityStore {
	private static final Logger LOG = LoggerFactory.getLogger(AwsSimpleDbRootCertificateAuthorityStore.class);
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	private AmazonSimpleDB sdb;
	private AmazonS3 s3;
	private String bucket;	// s3 bucket
	private String domain;	// Simple DB domain
	private String passcode;
	PasscodeGenerator auth;
	
	public AwsSimpleDbRootCertificateAuthorityStore() {
		Region usWest2 = Region.getRegion(Regions.US_WEST_2);
        sdb = new AmazonSimpleDBClient(new AwsMdmPropertiesCredentialsProvider());
		sdb.setRegion(usWest2);
		s3 = new AmazonS3Client(new AwsMdmPropertiesCredentialsProvider());
		s3.setRegion(usWest2);
		domain = MdmServiceProperties.getProperty(MdmServiceKey.awsSimpleDbRootCertificateAuthorityDomain);
		bucket = MdmServiceProperties.getProperty(MdmServiceKey.awsSimpleDbRootCertificateAuthorityBucket);
		
		Mac mac;
		try {
			mac = Mac.getInstance("HmacSHA1");
			String key = MdmServiceProperties.getProperty(MdmServiceKey.pkiAccessKey);
			mac.init(new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA1"));
			auth = new PasscodeGenerator(mac);
		} catch (NoSuchAlgorithmException|InvalidKeyException|UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void verify() throws RootCertificateAuthorityException {
		if (domain == null || bucket == null || auth == null || passcode == null) {
			throw new RootCertificateAuthorityException();
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public RootCertificateAuthority createCA(X509Certificate caCert,
			IssuerAndSerialNumber caIasn, X509Certificate raCert,
			PrivateKey raKey, boolean enabledState, String objectId)
			throws RootCertificateAuthorityException, GeneralSecurityException, IOException {

		verify();
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
		
		String blobKey = objectId+"/auth";
		// Set S3 object metadata and upload object data
		ObjectMetadata metadata = new ObjectMetadata();
		metadata.setCacheControl("no-cache");
		metadata.setContentDisposition(objectId + ".p12");
		metadata.setContentType("application/x-pkcs12");
        s3.putObject(new PutObjectRequest(bucket, blobKey, fin, metadata));

		List<ReplaceableAttribute> item = new ArrayList<ReplaceableAttribute>();
        item.add(new ReplaceableAttribute("IASN", caIasn.toString(), true));
        item.add(new ReplaceableAttribute("SerialCounter", "100", true));
        item.add(new ReplaceableAttribute("Enabled", new Boolean(enabledState).toString(), true));
        sdb.putAttributes(new PutAttributesRequest(domain, objectId, item));
		
        RootCertificateAuthority ca = new RootCertificateAuthority();
        ca.setConnector(new AwsSimpleDbRootCertificateAuthorityConnector(this, objectId, caCert, raCert, raKey));
        return ca;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void deleteCA(RootCertificateAuthority ca)
			throws RootCertificateAuthorityException, GeneralSecurityException, IOException {
		
		verify();
		X509CertificateHolder holder;
		IssuerAndSerialNumber caIasn;
		String selectExpression;
		List<Item> items;
		holder = new X509CertificateHolder(ca.getCaCertificate().getEncoded());
		caIasn = new IssuerAndSerialNumber(holder.getIssuer(), holder.getSerialNumber());
		selectExpression = "select * from `" + domain + "` where IASN = '" + caIasn.toString() + "'";
		SelectRequest selectRequest = new SelectRequest(selectExpression);
		items = sdb.select(selectRequest).getItems();
		
		// Select data from a domain
		// Must the use of backticks around the domain name in the select expression.
		// Should only contain one item
		if (items.size() > 1) {
			LOG.error("DeleteCA(IASN={}) - >1 select result", caIasn.toString());
			throw new RootCertificateAuthorityException();
		} else if (items.size() == 0) {
			LOG.debug("DeleteCA(IASN={}) - =0 select result", caIasn.toString());
			return;
		}
		
		Item item = items.get(0);
		String objectId = item.getName();
		
		// Now delete item
		LOG.info("DeleteCA(IASN={} and objectId={}) initiated", caIasn.toString(), objectId);
		sdb.deleteAttributes(new DeleteAttributesRequest(domain, objectId));
		s3.deleteObject(bucket, objectId+"/auth");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RootCertificateAuthority getCA(IssuerAndSerialNumber iasn) throws GeneralSecurityException, IOException, RootCertificateAuthorityException {
		String selectExpression;
		List<Item> items;
		verify();
		selectExpression = "select * from `" + domain + "` where IASN = '" + iasn.toString() + "'";
		SelectRequest selectRequest = new SelectRequest(selectExpression);
		items = sdb.select(selectRequest).getItems();
		if (items.size() == 1) {
			Item item = items.get(0);
			String objectId = item.getName();
            S3Object object = s3.getObject(new GetObjectRequest(bucket, objectId+"/auth"));
            
	        KeyStore store = KeyStore.getInstance("PKCS12", BC);
			passcode = auth.generateResponseCode(objectId.getBytes());
	    	
	        store.load(object.getObjectContent(), passcode.toCharArray());
	        
	        Key key = store.getKey(objectId, passcode.toCharArray());    
	        Certificate[] certs = store.getCertificateChain(objectId);
	        if (certs.length == 2) {
		        certs[0].verify(certs[1].getPublicKey());
		        certs[1].verify(certs[1].getPublicKey());
		        RootCertificateAuthority ca = new RootCertificateAuthority();
		        ca.setConnector(new AwsSimpleDbRootCertificateAuthorityConnector(this, 
		        					objectId, (X509Certificate)certs[1], 
		        					(X509Certificate)certs[0], (PrivateKey)key));
		        return ca;
	        } else {
	        	LOG.error("GetCA(IASN={}, objectId={}) has corrupted cert store", iasn.toString(), objectId);
	        	throw new RootCertificateAuthorityException();
	        }
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RootCertificateAuthority getCA(String objectId) throws GeneralSecurityException, IOException, RootCertificateAuthorityException {
		S3Object object = s3.getObject(new GetObjectRequest(bucket, objectId+"/auth"));
		
        KeyStore store = KeyStore.getInstance("PKCS12", BC);
		passcode = auth.generateResponseCode(objectId.getBytes());
    	
        store.load(object.getObjectContent(), passcode.toCharArray());
        
        Key key = store.getKey(objectId, passcode.toCharArray());    
        Certificate[] certs = store.getCertificateChain(objectId);
        if (certs.length != 2) {
        	LOG.error("GetCA(objectId={}) has corrupted cert store", objectId);
        	throw new RootCertificateAuthorityException();
        }
        certs[0].verify(certs[1].getPublicKey());
        certs[1].verify(certs[1].getPublicKey());
        RootCertificateAuthority ca = new RootCertificateAuthority();
        ca.setConnector(new AwsSimpleDbRootCertificateAuthorityConnector(this, 
        					objectId, (X509Certificate)certs[1], 
        					(X509Certificate)certs[0], (PrivateKey)key));
        return ca;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RootCertificateAuthorityResult getIssued(IssuerAndSerialNumber iasn) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RootCertificateAuthorityResult getIssued(String objectId) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long getNextSerialNumber() {
		// TODO Auto-generated method stub
		return 0;
	}

}
