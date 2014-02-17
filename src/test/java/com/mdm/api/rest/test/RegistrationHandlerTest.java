package com.mdm.api.rest.test;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.TestProperties;
import org.glassfish.jersey.test.inmemory.InMemoryTestContainerFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.mdm.api.EnrollmentManager;
import com.mdm.api.RegisterParentRequestData;
import com.mdm.api.rest.RegistrationHandler;
import com.mdm.utils.MdmServiceProperties;

public class RegistrationHandlerTest extends JerseyTest {
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	
	@Before
	public void setUp() throws Exception {
		setTestContainerFactory(new InMemoryTestContainerFactory());
		super.setUp();
        Security.addProvider(new BouncyCastleProvider());
		MdmServiceProperties.Initialize();
	}

	@After
	public void tearDown() throws Exception {
		super.tearDown();
		Security.removeProvider(BC); 
	}

	@Override
    protected Application configure() {
        // mvn test -DargLine="-Djersey.config.test.container.factory=org.glassfish.jersey.test.inmemory.InMemoryTestContainerFactory"
        // mvn test -DargLine="-Djersey.config.test.container.factory=org.glassfish.jersey.test.grizzly.GrizzlyTestContainerFactory"
        // mvn test -DargLine="-Djersey.config.test.container.factory=org.glassfish.jersey.test.jdkhttp.JdkHttpServerTestContainerFactory"
        // mvn test -DargLine="-Djersey.config.test.container.factory=org.glassfish.jersey.test.simple.SimpleTestContainerFactory"
		enable(TestProperties.LOG_TRAFFIC);
		//enable(TestProperties.DUMP_ENTITY);
		// maven-compile-plugin used google collections which conflicts with
		// guava. I disabled the com.google.collections dependency since Guava
		// is backward compatible.
		// Uncomment this line to see the dependency used.
		//System.out.println(com.google.common.collect.Iterables.class.getProtectionDomain().getCodeSource().getLocation());

        return new ResourceConfig(RegistrationHandler.class)
	        .packages("org.glassfish.jersey.examples.multipart")
	        .register(MultiPartFeature.class);
    }
	 
	@Test
	public void testRegistration() {
		RegisterParentRequestData data =  new 
				RegisterParentRequestData("user", "My Family", "Boise", "Idaho", "US");
		byte[] pkcs12 =  null;
		String objectId = null;
		try {
			Response resp = target("register").request().post(Entity.json(data));
			String filename = resp.getHeaderString("Content-Disposition");
			InputStream is = (InputStream)resp.getEntity();
			pkcs12 =  IOUtils.toByteArray(is);
			objectId = filename.substring(filename.indexOf("filename=", 0)+9, filename.indexOf(".p12", 0));
		} catch(Exception e) {
			//e.printStackTrace();
			fail();
		}
		
		// Cleanup
		try {
			Response resp = target("register/" + objectId).request().delete();
			assertTrue(!resp.hasEntity());
		} catch(Exception e) {
			//e.printStackTrace();
			fail();
		}
		
		// Verify keystore
		int i = 0;
		KeyStore keystore = null;
		try {
			ByteArrayInputStream fin = new ByteArrayInputStream(pkcs12);
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
		boolean verified = false;
		try {
			verified = EnrollmentManager.validateCertifcate(objectId, caCert);
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
		assertTrue(verified);
	}
	
	@Test
	public void testBadInput() {
		Response resp = null;
		try {
			RegisterParentRequestData data =  new 
					RegisterParentRequestData("", "My Family", "Boise", "Idaho", "US");
			resp = target("register").request().post(Entity.json(data));
		} catch(Exception e) {
			fail();
		}
		assertTrue(resp.getStatus() >= 400);

		try {
			String data = "{ \"name\":\"My Family\", \"city\":\"Boise\", \"state\":\"Idaho\", \"country\":\"US\"}";
			resp = target("register").request().post(Entity.entity(data, MediaType.APPLICATION_JSON));
		} catch(Exception e) {
			fail();
		}
		assertTrue(resp.getStatus() >= 400);

		try {
			String data = "{ \"muser\":\"me\", \"name\":\"My Family\", \"city\":\"Boise\", \"state\":\"Idaho\", \"country\":\"US\"}";
			resp = target("register").request().post(Entity.entity(data, MediaType.APPLICATION_JSON));
		} catch(Exception e) {
			fail();
		}
		assertTrue(resp.getStatus() >= 400);

		try {
			resp = target("register" + "abcdefghigklmnopqrstuvwxyz" ).request().delete();
			assertTrue(!resp.hasEntity());
		} catch(Exception e) {
			fail();
		}
		assertTrue(resp.getStatus() >= 400);
	}
}
