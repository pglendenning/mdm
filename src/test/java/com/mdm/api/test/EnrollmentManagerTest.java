package com.mdm.api.test;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Enumeration;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.mdm.api.EnrollmentHolder;
import com.mdm.api.EnrollmentManager;
import com.mdm.api.InvalidObjectIdException;
import com.mdm.api.OperationFailedException;
import com.mdm.api.RegisterParentRequestData;
import com.mdm.api.RegisterParentResponseData;
import com.mdm.cert.AwsCertificateAuthorityStore;
import com.mdm.cert.CertificateAuthority;
import com.mdm.cert.CertificateAuthorityException;
import com.mdm.cert.X509CertificateGenerator;
import com.mdm.utils.MdmServiceProperties;

public class EnrollmentManagerTest {
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	EnrollmentManager mgr = null;

	@Before
	public void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
		MdmServiceProperties.Initialize();
        mgr = new EnrollmentManager(new AwsCertificateAuthorityStore());
	}

	@After
	public void tearDown() throws Exception {
		Security.removeProvider(BC); 
	}

	public void testEnrollmentManagerICertificateAuthorityStore() {
		fail("Not yet implemented");
	}

	public void testEnrollmentManagerICertificateAuthorityStoreIntInt() {
		fail("Not yet implemented");
	}

	public void testGetObjectIdFromCertifcate() {
		fail("Not yet implemented");
	}

	@Test
	public void testRegistration() {
		// REGISTER
		RegisterParentRequestData data = new RegisterParentRequestData("abcdef", "EnrollmentManagerTest", "Woodside", "California", "US");
		int i = 0;
		KeyStore keystore = null;
		String objectId = null;
		try {
			RegisterParentResponseData result = mgr.registerParentDevice(data);
			ByteArrayInputStream fin = new ByteArrayInputStream(result.getPkcs12());
			keystore = KeyStore.getInstance("PKCS12", BC);
	
			keystore.load(fin, data.getUserId().toCharArray());
	        
	        Enumeration<?> enumeration = keystore.aliases();
	        while (enumeration.hasMoreElements()) {
	            enumeration.nextElement();
	            ++i;
	        }
	        objectId = result.getObjectId();
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
        assertTrue(i == 1);
        Key key = null;
		try {
			key = keystore.getKey(data.getFriendlyName(), data.getUserId().toCharArray());
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
        assertTrue(key != null);
        Certificate[] certs = null;
		try {
			certs = keystore.getCertificateChain(data.getFriendlyName());
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
        assertTrue(certs.length == 1);
		try {
	        certs[0].verify(certs[0].getPublicKey());
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
		
		X509Certificate caCert = (X509Certificate)certs[0];
		boolean verified = false;
		try {
			verified = EnrollmentManager.validateCertifcate(objectId, caCert);
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
		assertTrue(verified);
		CertificateAuthority ca = null;
		AwsCertificateAuthorityStore store = new AwsCertificateAuthorityStore();
		try {
			ca = store.getCA(objectId);
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
		assertTrue(ca != null);
		
		// UNREGISTER
		try {
			mgr.unregisterParentDevice(objectId);
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
		
		try {
			ca = store.getCA(objectId);
		} catch (Exception e) {
			ca = null;
		}
		assertTrue(ca == null);
	}
	
	private String init() {
		try {
	        KeyFactory fact = KeyFactory.getInstance("RSA", BC);
			MdmServiceProperties.Initialize();
			AwsCertificateAuthorityStore store = new AwsCertificateAuthorityStore();
			String parentId = Long.toString(Calendar.getInstance().getTimeInMillis(), 32);
	
			PrivateKey caPriv = fact.generatePrivate(new RSAPrivateCrtKeySpec(
						new BigInteger("b19fda976e289cbb25c3885f106ec021f09cdb826e7ee64ede7bf93e6ff1d87ffa92b0d7bd0cf9f7d99762ce4ba235e6ec8ee601ffe3b1d669f4835ece0aeba609055b55219e06e09b0312754c0a3d2cd24f50ce885fca56737e1a0cf965cdfd82705da658d2940fbf3557aecff6cfc9809871ac0d323585c732213ae66b33b1", 16),
						new BigInteger("10001", 16),
						new BigInteger("9b5673326f7230ef322d783bbb014021ee6d1f434822ce8336eb30a43bfe431a5926a46567bdcb75c7e32ed3bf2d52fa6af2e58fe61b58d16cc41b8773a5f5423cac86ad73498855e0e0251e4cddfcfcf7a8093bb79833407bcabf6d689ed8306b6acf58dc6b7032c4215ab70cdd041ae66df65adef97c9f4d132f6aaee34769", 16),
						new BigInteger("f4a6479e90ddd9d4c37eafe0ade8114fd2942315f40f209e9c3e9fcc51861f31ef830f7979058354557d4fcedcf0f001d88532337429e0573743e11372ec3533", 16),
						new BigInteger("b9dd831a14f9e77ea0ef557b7f5b6f20580391d3fb9c4e4f637e914efe4f8a90b4a2b34f5dd4759666ac0e72a72710d52dd8bfe1fc7c19b7fbd30083a65a6b8b", 16),
						new BigInteger("158bff8acb9f7e6beabbe1a99c27703ee38100861274b29ec58c0e6ee44f37b8222c1cd4c9ffde4d332a523919e46e7efb1ee009001620180e5a001cc2666359", 16),
						new BigInteger("601fe5bbc9796d7619f96d764f6994515ff388a9df88f91f29cfbd8ae30f74145eb77e90df700fd8570548fb96e3275b79388e146c262a8ef2982fbde67d00fd", 16),
						new BigInteger("99f7163d85cf89036227a989ceaecc08ae830ab3a33c556d4496046bebef67f43524c5c06d4e66579b68a71600cdcfc34265d2ca27700456932a524f310a2d0f", 16)));
	    	PublicKey caPub = fact.generatePublic(
					new RSAPublicKeySpec(
						new BigInteger("b19fda976e289cbb25c3885f106ec021f09cdb826e7ee64ede7bf93e6ff1d87ffa92b0d7bd0cf9f7d99762ce4ba235e6ec8ee601ffe3b1d669f4835ece0aeba609055b55219e06e09b0312754c0a3d2cd24f50ce885fca56737e1a0cf965cdfd82705da658d2940fbf3557aecff6cfc9809871ac0d323585c732213ae66b33b1", 16),
						new BigInteger("10001", 16)));
	    	
	    	PrivateKey raPriv = fact.generatePrivate(
	    			new RSAPrivateCrtKeySpec(
	    				new BigInteger("a5226e241a19f5b796ef2326f4f580b1e5cbc05360a7fd94fd8d59013115e077a422beb4904c5e57f0d9827a0da98b337ab8d47a2b24f77d83f9689e9b43af6b23bf39a1e4e87d8ce9f7d68b8dd50ffec1d34b25833848325ed035d3a1ddeaf62fe5a184dec918d7c2e8b89b17b057a9af359280956dc2a393be6e9a04517b25", 16),
	    				new BigInteger("10001", 16),
	    				new BigInteger("6ff223507e11532e1e380750858758b340e11b846a65f7d664fcc975b15cef4aac0e91d1be70c7143ec6755960a1ab283eedc5bcfc3a973c9397248141286565d479dd57d9bc01d4dec645dd1ae01590671315ec6f9bcde606707255382fcb363744a8bcda3c7a3c2e4015d450ed4aafb675ae277ddcf0e779165125a84f6681", 16),
	    				new BigInteger("f8e745cf5388418a0f038b425095aa8ce3cae42764c15d6f91021a0b6fe0746653428ac95c88ce127deae745521805b6a53da780b56c3f4d15f0c88a85a19609", 16),
	    				new BigInteger("a9d7bc0903893d8116ad8df22e425df382f895d47c0a47d7ea182e9a6221f3d1b27cdfd278960d8cc65699a5c1e5e17197805c9954ff6c37c19a0d9e2241a33d", 16),
	    				new BigInteger("88181ca9a228ec7d0a7c8b9674ed80d58c701194209941f790b82f797570aaf4902de028fdb9a7c3a0a9e24e9af69b99247cb3abc2872f8d7ca3ad636071dbd1", 16),
	    				new BigInteger("5f024cb0aa26ba9e1cc68772238882aff6e30245b401b840c33635d3acf39b4601d7b30934e593bcdd32928ed411b97466b0aa9c279d1eb76df8b48772584f6d", 16),
	    				new BigInteger("e9774efb165c4309e7c7f32603d882d2e8b728887ddb50ee2c2e89591d192b64058699d3251e01348ee24dd23669aec43f1b4e16266950f6268e632242b7d500", 16)));
	    	PublicKey raPub = fact.generatePublic(
	    			new RSAPublicKeySpec(
	    				new BigInteger("a5226e241a19f5b796ef2326f4f580b1e5cbc05360a7fd94fd8d59013115e077a422beb4904c5e57f0d9827a0da98b337ab8d47a2b24f77d83f9689e9b43af6b23bf39a1e4e87d8ce9f7d68b8dd50ffec1d34b25833848325ed035d3a1ddeaf62fe5a184dec918d7c2e8b89b17b057a9af359280956dc2a393be6e9a04517b25", 16),
	    				new BigInteger("10001", 16)));
	    	
			// Create self signed CA
	        X509Certificate caCert = X509CertificateGenerator.createV3RootCA(
	        		caPub,
	        		caPriv,
	        		1,
	        		2,
	        		"CN=" + parentId + ", C=US, ST=California, L=Woodside ,O=Acme Inc,OU=Root Certificate", 
	        		null, null);	// set issuer=subject
	        X509Certificate raCert = X509CertificateGenerator.createCert(
	        		raPub,
	        		caCert,
	        		caPriv,
	        		2, caCert.getNotAfter(),
	        		"CN=Pablobill, C=US, ST=California, L=Woodside,O=Acme Inc.,OU=EndEntity Certificate",
	        		null, null);
			store.addCA(caCert, raCert, raPriv, 10, true, parentId);
			return parentId;
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
		return null;
	}

	private void cleanUp(String parentId) {
		AwsCertificateAuthorityStore store = new AwsCertificateAuthorityStore();
		try {
			store.removeCA(parentId);
		} catch (CertificateAuthorityException e) {
			fail("Exception:" + e.getMessage());
		}
	}
	
	public void testStartNewEnrollment() {
		String parentId = init();
		EnrollmentManager mgr = new EnrollmentManager(new AwsCertificateAuthorityStore());
		EnrollmentHolder  holder = null;
		try {
			holder = mgr.startNewEnrollment(parentId, "My Family");
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
		
		cleanUp(parentId);
	}

	public void testCleanUpEnrollments() {
		fail("Not yet implemented");
	}

	public void testGetEnrollment() {
		fail("Not yet implemented");
	}

	public void testIsValidParentId() {
		fail("Not yet implemented");
	}

}
