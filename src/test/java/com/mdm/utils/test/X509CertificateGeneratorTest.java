package com.mdm.utils.test;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mdm.utils.RSAKeyPair;
import com.mdm.utils.X509CertificateGenerator;

public class X509CertificateGeneratorTest {
	private static final Logger LOG = LoggerFactory.getLogger(X509CertificateGeneratorTest.class);
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
	
	        myKeys.generate();	
	        chain[0] = X509CertificateGenerator.createCert(
	        		myKeys.getPublicKey(),
	        		(X509Certificate) chain[1],
	        		intKeys.getPrivateKey(),
	        		1, 365,
	        		"L=US,O=Acme Inc.,OU=EndEntity Certificate,CN=Paul Glendenning",
	        		"http://www/acme.com/crl1.lst;http://www/acme.com/crl2.lst",
	        		"Leaf Certificate");
	                
			//FileOutputStream fOut = new FileOutputStream("X509CertificateGeneratorTest.p12");
			ByteArrayOutputStream fOut = new ByteArrayOutputStream();
			X509CertificateGenerator.savePKCS12(fOut, "Pauls' Key","junk", myKeys.getPrivateKey(), chain);
			
			// read back
			//FileInputStream fin = new FileInputStream("X509CertificateGeneratorTest.p12");
			ByteArrayInputStream fin = new ByteArrayInputStream(fOut.toByteArray());
	        KeyStore store = KeyStore.getInstance("PKCS12", BC);
	
	        store.load(fin, "junk".toCharArray());
	        
	        Enumeration<?> enumeration = store.aliases();
	        int i = 0;
	        while (enumeration.hasMoreElements()) {
	            String alias = (String)enumeration.nextElement();
	            //LOG.debug("alias name: {}", alias);
	            Certificate certificate = store.getCertificate(alias);
	            //LOG.debug(certificate.toString());
	            ++i;
	        }
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
