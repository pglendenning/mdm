package com.mdm.api.test;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.mdm.api.EnrollmentManager;
import com.mdm.api.RegisterParentRequestData;
import com.mdm.cert.AwsCertificateAuthorityStore;
import com.mdm.cert.CertificateAuthority;
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
		try {
			byte[] result = mgr.registerParentDevice(data);
			ByteArrayInputStream fin = new ByteArrayInputStream(result);
			keystore = KeyStore.getInstance("PKCS12", BC);
	
			keystore.load(fin, data.getUserId().toCharArray());
	        
	        Enumeration<?> enumeration = keystore.aliases();
	        while (enumeration.hasMoreElements()) {
	            enumeration.nextElement();
	            ++i;
	        }
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
		String objectId = null;
		try {
			objectId = EnrollmentManager.getObjectIdFromCertifcate(caCert);
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
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

	public void testStartNewEnrollment() {
		fail("Not yet implemented");
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
