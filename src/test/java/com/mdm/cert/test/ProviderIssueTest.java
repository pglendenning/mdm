package com.mdm.cert.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import static org.junit.Assert.fail;

import org.jscep.client.inspect.CertStoreInspector;
import org.jscep.client.inspect.DefaultCertStoreInspectorFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class ProviderIssueTest {
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	private static long serialNum = 1;
	
	@Before
	public void setUp() {
        Security.addProvider(new BouncyCastleProvider());		
	}
	
	@After
	public void tearDown() throws Exception {
		Security.removeProvider(BC); 
	}

    /**
     * Create a v3 self signed root certificate.
     */
	public static X509Certificate createV3RootCA(PublicKey pubKey, PrivateKey  privKey, 
				int durationInDays,
				String subject, String issuer) throws Exception {
    	
    	if (issuer == null)
    		issuer = subject;

        // Mandatory
        Calendar calendar = Calendar.getInstance();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.DATE, durationInDays);
        Date notAfter = calendar.getTime();
        BigInteger issuerSerialNumber = BigInteger.valueOf(serialNum++);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
        		new X500Principal(issuer),
        		issuerSerialNumber,
        		notBefore, notAfter,
        		new X500Principal(subject),
        		pubKey);
        
        // Optional extensions
        certBuilder.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(true));
        certBuilder.addExtension(X509Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign|KeyUsage.cRLSign|KeyUsage.digitalSignature));
        // Signing
        ContentSigner certSigner = new JcaContentSignerBuilder("SHA1WithRSA")
        							.setProvider(BC)
        							.build(privKey);
        X509CertificateHolder certHolder = certBuilder.build(certSigner);

 
        // Extract a JCA-compatible certificate
        X509Certificate cert = new JcaX509CertificateConverter()
        				.setProvider(BC).getCertificate(certHolder);
        
        cert.checkValidity(new Date());
        cert.verify(pubKey);
        return cert;
    }
	
    /**
     * Generate a leaf certificate signed by a CA
     */
	public static X509Certificate createCert(PublicKey pubKey, X509Certificate caCert, PrivateKey caPrivKey,
				int durationInDays,
				String subject) throws Exception {
    	
        // Mandatory
        Calendar calendar = Calendar.getInstance();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.DATE, durationInDays);
        Date notAfter = calendar.getTime();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
        		caCert.getSubjectX500Principal(),
        		BigInteger.valueOf(serialNum++),
        		notBefore, notAfter,
        		new X500Principal(subject),
        		pubKey);

        // Optional extensions
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(X509Extension.basicConstraints, false, new BasicConstraints(false));
        certBuilder.addExtension(X509Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature|KeyUsage.keyEncipherment));
        certBuilder.addExtension(X509Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pubKey));
        certBuilder.addExtension(X509Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert));

        // Signing
        ContentSigner certSigner = new JcaContentSignerBuilder("SHA1WithRSA")
        			.setProvider(BC).build(caPrivKey);

        X509CertificateHolder certHolder = certBuilder.build(certSigner);

        // Extract a JCA-compatible certificate
        X509Certificate cert = new JcaX509CertificateConverter()
        			.setProvider(BC).getCertificate(certHolder);
        
        cert.checkValidity(new Date());
        cert.verify(caCert.getPublicKey());
        return cert;
    }
	
	@Test
	public void test() throws Exception {

		KeyFactory fact = KeyFactory.getInstance("RSA", BC);
 
		PrivateKey caPriv = fact.generatePrivate(
				new RSAPrivateCrtKeySpec(
					new BigInteger("a5226e241a19f5b796ef2326f4f580b1e5cbc05360a7fd94fd8d59013115e077a422beb4904c5e57f0d9827a0da98b337ab8d47a2b24f77d83f9689e9b43af6b23bf39a1e4e87d8ce9f7d68b8dd50ffec1d34b25833848325ed035d3a1ddeaf62fe5a184dec918d7c2e8b89b17b057a9af359280956dc2a393be6e9a04517b25", 16),
					new BigInteger("10001", 16),
					new BigInteger("6ff223507e11532e1e380750858758b340e11b846a65f7d664fcc975b15cef4aac0e91d1be70c7143ec6755960a1ab283eedc5bcfc3a973c9397248141286565d479dd57d9bc01d4dec645dd1ae01590671315ec6f9bcde606707255382fcb363744a8bcda3c7a3c2e4015d450ed4aafb675ae277ddcf0e779165125a84f6681", 16),
					new BigInteger("f8e745cf5388418a0f038b425095aa8ce3cae42764c15d6f91021a0b6fe0746653428ac95c88ce127deae745521805b6a53da780b56c3f4d15f0c88a85a19609", 16),
					new BigInteger("a9d7bc0903893d8116ad8df22e425df382f895d47c0a47d7ea182e9a6221f3d1b27cdfd278960d8cc65699a5c1e5e17197805c9954ff6c37c19a0d9e2241a33d", 16),
					new BigInteger("88181ca9a228ec7d0a7c8b9674ed80d58c701194209941f790b82f797570aaf4902de028fdb9a7c3a0a9e24e9af69b99247cb3abc2872f8d7ca3ad636071dbd1", 16),
					new BigInteger("5f024cb0aa26ba9e1cc68772238882aff6e30245b401b840c33635d3acf39b4601d7b30934e593bcdd32928ed411b97466b0aa9c279d1eb76df8b48772584f6d", 16),
					new BigInteger("e9774efb165c4309e7c7f32603d882d2e8b728887ddb50ee2c2e89591d192b64058699d3251e01348ee24dd23669aec43f1b4e16266950f6268e632242b7d500", 16)));
		PublicKey caPub = fact.generatePublic(
				new RSAPublicKeySpec(
					new BigInteger("a5226e241a19f5b796ef2326f4f580b1e5cbc05360a7fd94fd8d59013115e077a422beb4904c5e57f0d9827a0da98b337ab8d47a2b24f77d83f9689e9b43af6b23bf39a1e4e87d8ce9f7d68b8dd50ffec1d34b25833848325ed035d3a1ddeaf62fe5a184dec918d7c2e8b89b17b057a9af359280956dc2a393be6e9a04517b25", 16),
					new BigInteger("10001", 16)));
		
		PublicKey usrPub = fact.generatePublic(
    			new RSAPublicKeySpec(
    				new BigInteger("84d4269505c38ba8c5fee8619cf0442eb55c31ae76ec430c1bbe3c82e48a1b56c6f2a3449edf044bcb7151b5df289182b685456f60f819ff7307478fe24f322c6afd4beae7bb4ad50c8bb26c9d0bd505cd91afb144003bea1d2c7fd743178d0141789aca69a5a97918dfccf7d82b25b1bf952cf06f9f432b338ddb773f79583dbbbeaf9fc4cf0878154fdcdfff160b3b5c1ed713990264ab97a3c0a5c617fe123395c03bf94ab24e3f7120ab7d95d06aa83ec9481566b1b6c2dcc9047a46abbf8ee43b32b5589edca36b3342073eb6bf8838a397363bf567640c1d0536961c125b81c0d31d09bd08171b1b6ca9343e09cfa7e3a6010e98d46da7cb6adccf52d5", 16),
    				new BigInteger("10001", 16)));
		
		// Create self signed CA
        X509Certificate caCert = createV3RootCA(
        		caPub,
        		caPriv,
        		365,
        		"CN=Root Test, C=US, ST=California, L=Woodside ,O=Acme Inc,OU=Root Certificate", 
        		null);	// set issuer=subject
        X509Certificate usrCert = createCert(
        		usrPub,
        		caCert,
        		caPriv,
        		365,
        		"CN=Pablobill, C=US, ST=California, L=Woodside,O=Acme Inc.,OU=EndEntity Certificate");
        
        // Always passes
        caCert.verify(caCert.getPublicKey());
        usrCert.verify(caCert.getPublicKey());
        
        try {
    		// PROVIDER 1
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "SUN"); 
            Certificate CA = cf.generateCertificate(new ByteArrayInputStream(caCert.getEncoded()));        	
            Certificate UA = cf.generateCertificate(new ByteArrayInputStream(usrCert.getEncoded()));        	
            CA.verify(CA.getPublicKey());	// This always works irrespective of the provider
            UA.verify(CA.getPublicKey());	// This always works irrespective of the provider
            ArrayList<Certificate> alist = new ArrayList<Certificate>(2);
            alist.add(UA);
            alist.add(CA);
       		// PROVIDER 2
    		CertStore certStore = CertStore.getInstance("Collection", 
    					new CollectionCertStoreParameters(alist), "SUN");
    		
    		DefaultCertStoreInspectorFactory inspectFactory = new DefaultCertStoreInspectorFactory();
    		CertStoreInspector inspector = inspectFactory.getInstance(certStore);
    		
    		X509Certificate UB = inspector.getRecipient();
    		X509Certificate CB = inspector.getIssuer(); 
            
            //LOG.debug("UB.length={}, UA.length={}, UB ={}", UB.getEncoded().length, UA.getEncoded().length, UB);
            //LOG.debug("CB.length={}, CA.length={}, CB ={}", CB.getEncoded().length, CA.getEncoded().length, CB);
            
            // This always works if provider 2 is "BC", provider 1 can be either "SUN" or "BC".
            // Fails if provider 2 is "SUN" and provider 1 is "SUN" 
        	UA.verify(CB.getPublicKey());
        	CA.verify(CB.getPublicKey());

        	// Works sometimes if provider 2 is "SUN", Always works if provider 2 is "BC"
        	UB.verify(CB.getPublicKey());
            CB.verify(CB.getPublicKey());
            
        	//LOG.debug("SUCCESS");
            
        } catch (Exception e) {
        	e.printStackTrace();
            fail();
        }
	}
}





