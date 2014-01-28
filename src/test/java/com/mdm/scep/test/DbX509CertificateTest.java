package com.mdm.scep.test;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mdm.scep.DbRootCertificateAuthorityStore;
import com.mdm.utils.RSAKeyPair;
import com.mdm.utils.X509CertificateGenerator;

public class DbX509CertificateTest {
	private static final Logger LOG = LoggerFactory.getLogger(DbX509CertificateTest.class);
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	
	@Before
	public void setUp() {
        Security.addProvider(new BouncyCastleProvider());		
	}
	
	@After
	public void tearDown() {
		Security.removeProvider(BC);
	}
	
	@Test
	public void test() {
		
		DbRootCertificateAuthorityStore DbRootCertAuthStore = new DbRootCertificateAuthorityStore();
		
		System.out.println("Starting x509CertificateGeneratorTest");
        
		try {
			RSAKeyPair	caKeys = new RSAKeyPair();
			RSAKeyPair	intKeys = new RSAKeyPair();
			RSAKeyPair	myKeys = new RSAKeyPair();
	
	        Certificate[] chain = new Certificate[3];
	    	
	        caKeys.generate();
	        chain[2] = X509CertificateGenerator.createV3RootCA(
	        		caKeys.getPublicKey(),
	        		caKeys.getPrivateKey(),
	        		1, 365,
	        		"CN=Root Test, L=US,O=Acme Inc,OU=Root Certificate", 
	        		null,	// set issuer=subject
	        		"Root Certificate");        
		  
	        
	        intKeys.generate();
	        chain[1] = X509CertificateGenerator.createIntermediateCA(
	        		intKeys.getPublicKey(),
	        		(X509Certificate) chain[2],
	        		caKeys.getPrivateKey(),
	        		2, 365,
	        		"CN=Intermediate Test, L=US,O=Acme Inc.,OU=Intermediate Certificate",
	        		null,
	        		"Intermediate Certificate");
	        
System.out.println("Starting x509CertificateGeneratorTest 2");  
	
	        myKeys.generate();	
	        chain[0] = X509CertificateGenerator.createCert(
	        		myKeys.getPublicKey(),
	        		(X509Certificate) chain[1],
	        		intKeys.getPrivateKey(),
	        		1, 365,
	        		"L=US,O=Acme Inc.,OU=EndEntity Certificate,CN=Paul Glendenning",
	        		"http://www/acme.com/crl1.lst;http://www/acme.com/crl2.lst",
	        		"Leaf Certificate");
	     
	        System.out.println("Starting x509CertificateGeneratorTest 3");  
	        
	        IssuerAndSerialNumber caIasn = X509CertificateGenerator.getIssuerAndSerialNumber((X509Certificate) chain[2]);
	       
	        System.out.println("Starting x509CertificateGeneratorTest 3.5");  
	        DbRootCertAuthStore.createCA((X509Certificate) chain[2], caIasn, (X509Certificate) chain[1], intKeys.getPrivateKey(), true);
	        
	        
	  System.out.println("Starting x509CertificateGeneratorTest 4"); 
	                
			//FileOutputStream fOut = new FileOutputStream("X509CertificateGeneratorTest.p12");
			ByteArrayOutputStream fOut = new ByteArrayOutputStream();
			X509CertificateGenerator.savePKCS12(fOut, "Pauls' Key","junk", myKeys.getPrivateKey(), chain);
			
			// read back
			//FileInputStream fin = new FileInputStream("X509CertificateGeneratorTest.p12");
			ByteArrayInputStream fin = new ByteArrayInputStream(fOut.toByteArray());
	        KeyStore store = KeyStore.getInstance("PKCS12", BC);
	
	 System.out.println("Starting x509CertificateGeneratorTest 5"); 
	
	        store.load(fin, "junk".toCharArray());
	        
	        Enumeration<?> enumeration = store.aliases();
	        int i = 0;
	        while (enumeration.hasMoreElements()) {
	            String alias = (String)enumeration.nextElement();
	            
	    		//System.out.println("alias name: " + alias);
	            //LOG.debug("alias name: {}", alias);
	            Certificate certificate = store.getCertificate(alias);
	            //LOG.debug(certificate.toString());
	            //System.out.println("Cert.toString(): " + certificate.toString());
	            ++i;
	        }
	        
System.out.println("Starting x509CertificateGeneratorTest 6"); 
	  	  
	        assertTrue(i == 3);
	        Key key = store.getKey("Pauls' Key", "junk".toCharArray());
	        assertTrue(key != null);
	        
	        Certificate[] certs = store.getCertificateChain("Pauls' Key");
	        assertTrue(certs.length == 3);
	        certs[0].verify(certs[1].getPublicKey());
	        certs[1].verify(certs[2].getPublicKey());
	        certs[2].verify(certs[2].getPublicKey());
	        
		} catch (Exception e) {			
			fail();
		}
	}
}
