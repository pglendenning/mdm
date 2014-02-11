package com.mdm.cert.scep.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.ServletTester;
import org.jscep.client.CertificateVerificationCallback;
import org.jscep.client.Client;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.inspect.CertStoreInspector;
import org.jscep.client.inspect.DefaultCertStoreInspectorFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mdm.cert.RSAKeyPair;
import com.mdm.cert.X509CertificateGenerator;
import com.mdm.cert.scep.MdmScepServlet;
import com.mdm.utils.MdmServiceProperties;


public class MdmScepServletTest implements CallbackHandler {
	private static final Logger LOG = LoggerFactory.getLogger(MdmScepServletTest.class);
    private X509Certificate caCert;
    private RSAKeyPair clientKeys;
    private X509Certificate clientCert;
    private ServletTester server;
    private String BC = BouncyCastleProvider.PROVIDER_NAME;
    private String clientSubject = "CN=ScepClient, O=Mdm Client, OU=Unit Test, C=US, ST=California, L=Woodside";
    private String uri;
    
    /*
     * CallbackHandler method
     */
	public boolean verify(X509Certificate cert) {
        return true;
    }

    /*
     * CallbackHandler method
     */
	@Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        // Loop through all the callbacks.  There will only ever be one.
        for (int i = 0; i < callbacks.length; i++) {
            // Check that the callback is a CertificateVerificationCallback
            if (callbacks[i] instanceof CertificateVerificationCallback) {
                // Cast the callback
                CertificateVerificationCallback callback = (CertificateVerificationCallback) callbacks[i];
                // Check the certificate
                callback.setVerified(verify(callback.getCertificate()));
            } else {
                // If we don't know the type of callback, throw an exception
                throw new UnsupportedCallbackException(callbacks[i]);
            }
        }
    }

	@Before
	public void setUp() throws Exception {
		
		MdmScepServlet.setIncludeCACertInEnrollResponse(true);
		MdmServiceProperties.Initialize();
		
		// Create CA key pair
        Security.addProvider(new BouncyCastleProvider());
		// Create client key pair
        MdmScepServletTestFilter.init();
        
        // PKI is not thread safe so must do deep copy since server is
        // in another thread.
        caCert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(new JcaX509CertificateHolder(MdmScepServletTestFilter.caCert));
        
		clientKeys = new RSAKeyPair();
		clientKeys.generate(
			new RSAPrivateCrtKeySpec(
				new BigInteger("b447bdace3bc4f20f18b7261e74183b13b8db967ba040ab78b0824ba1b1cbd3aa4b2c5a3d13835da2e4b575074605598a62464f49ccd51b4b420cdaacf7a1dc8f3a22c33efebfa2818f653de7c3d33500e815503138719af529f827ea00f9143652b8067cf4242cf3c705a7e0dc4a8391257a79a7ccc4efc78c9db85028c6e69", 16),
				new BigInteger("10001", 16),
				new BigInteger("128a5e436d986c3ae31c8842f15997859eae50a70e466423c434ae32459f8b0680f1b1c9cb3690b3439793ff3e38ba14dce159509edfaecb7acaf4dbe0429ad5672f67a1baf8c52165f9033821e4022e4fd52545dfb7493e5ffd8180c05e9867a86ea7eeb49ace1cec72bc37dfca1586a2b613b6f9f1ae0819e9d1dd732fd391", 16),
				new BigInteger("f8b4b3311888e1ebe222c31d1aa266f0d49dbdbc58407d5406a325033b75b99bc658544a5eaade4b3dc5e6bd6a7d1379aa6d8589a16da822a97703a6fd04e40f", 16),
				new BigInteger("b9914bff3f83e84b97d13dc2402ccc9673a47f9cd66d50efd617f5a1000c84eb8033068970d67de5e43e40e8bf28fe4f93cb80d453853e1aaf7f5de56d18ae07", 16),
				new BigInteger("a9ddf1ce04ade970cd21651689cc8676d32172282436d7e2fe2d8be82b427b2574517c30d77be91c86f29668a5450c7a3af7570febdc13cca8e68aee113eb7ed", 16),
				new BigInteger("6be70ce5d32d047a50411f4440c4cc0200247affdbbf9cfc98e53db2ecb05aea0595a60b6d4d8bcf8db49551c136390a54ca5493222dac3b2029539400a80529", 16),
				new BigInteger("970d0c849535a9f51544f2b8baa5bdc2aecf90ca37561070c5aebac4eb59be510066c85a1d4d9c610353826347accdf21758663cb0e7d05f2bcae31c7c3f2915", 16)),
			new RSAPublicKeySpec(
				new BigInteger("b447bdace3bc4f20f18b7261e74183b13b8db967ba040ab78b0824ba1b1cbd3aa4b2c5a3d13835da2e4b575074605598a62464f49ccd51b4b420cdaacf7a1dc8f3a22c33efebfa2818f653de7c3d33500e815503138719af529f827ea00f9143652b8067cf4242cf3c705a7e0dc4a8391257a79a7ccc4efc78c9db85028c6e69", 16),
				new BigInteger("10001", 16)));

     	//LOG.debug("------- OUR PRIVATE KEY ----------\n{}\n----OUR PUBLIC KEY-------\n{}\n---------------------", clientKeys.getPrivateKey(), clientKeys.getPublicKey());
		clientCert = X509CertificateGenerator.createV3RootCA(clientKeys.getPublicKey(), 
					clientKeys.getPrivateKey(), 1, 2, 
					clientSubject, 
					null, null);
		
    	// Init server
        String url;
		server = new ServletTester();
		server.setContextPath("/");
		server.addFilter(MdmScepServletTestFilter.class, "/scep/*", null);
		server.addServlet(MdmScepServlet.class, "/scep/pkiclient.exe");
		server.addServlet(DefaultServlet.class, "/");
		url = server.createConnector(true);
		server.setAttribute(MdmScepServlet.SESSION_PASSWD, "secret");		
		server.start();
		
		uri = url + "/scep/pkiclient.exe";
	}

	@After
	public void tearDown() throws Exception {
		if (server != null) {
			synchronized(server) {
				server.notify();
				server.stop();
			}
		}
		Security.removeProvider(BC); 
	}

	@Test
	public void testEnrollment() {
        try {
            // Init client
            Client client = new Client(new URL(uri), this);
            /*
            RSAKeyPair ourKeys = new RSAKeyPair();
        	ourKeys.generate(
        			new RSAPrivateCrtKeySpec(
        				new BigInteger("84d4269505c38ba8c5fee8619cf0442eb55c31ae76ec430c1bbe3c82e48a1b56c6f2a3449edf044bcb7151b5df289182b685456f60f819ff7307478fe24f322c6afd4beae7bb4ad50c8bb26c9d0bd505cd91afb144003bea1d2c7fd743178d0141789aca69a5a97918dfccf7d82b25b1bf952cf06f9f432b338ddb773f79583dbbbeaf9fc4cf0878154fdcdfff160b3b5c1ed713990264ab97a3c0a5c617fe123395c03bf94ab24e3f7120ab7d95d06aa83ec9481566b1b6c2dcc9047a46abbf8ee43b32b5589edca36b3342073eb6bf8838a397363bf567640c1d0536961c125b81c0d31d09bd08171b1b6ca9343e09cfa7e3a6010e98d46da7cb6adccf52d5", 16),
        				new BigInteger("10001", 16),
        				new BigInteger("341584337719205043a31ab7fbf3f2a866110aa2209bb006b5723904125d5d2effbff0e95d6a91a2aed97672dc586a06594f94d481af87723546ab76ee04a3e5eae5fbb8d6b90834d64088ec32008bbd44c8559e2acdf4b06e541ea4e7f7fa207dedaeb4a40c8391aa81473c00159b2841b95aefc4b52c7f6a2dbbdadc96d6547dfd74b25ccddfcf3bdea3175322e70bb99f8d56e4c5daccfb551bb8ab25755d0f7ab17ecc8b426e7757eeedc19fc4e06270268da33a14d398aeeb745ae1f06ed8fadf51b46390edb5cd4feb042757886bf2d0a4dde903c8ae92aaea9580726ee0a8ce16abc9c176332db1f48a6bf238d3400d446099f67e7c1180600d0b4e81", 16),
        				new BigInteger("bc7766d15d55cb9c67d691028f39a7185e61d43524411a091573059c5ae3df2fd0272cb9e9354a598503c25ed8d27065406666f67d0bf02cbbb52c9f2a9e58e02f39a7a4b7fdb51b5ca1f43659760736d636628a96c04184d93575fe1238db941dcca684d5a66eba2d925b3e6f2728e618dc87e2d6195ff2aedf4e742e8307c5", 16),
        				new BigInteger("b46ceef3b9ef7fb60b7ec40b9914b19d230af1789ad77da6b0f350afa75a214a38f4fdecfe3b3b45101d7dcd491e66d046a08728e9bee97d4d33905445e4573f78c0c9d23620067e01b864c20a3f135aad3c163769e3ba3e5e043e3773f304ed8b460f73db32a3c1f62ab826224c133300345f0ba6d2018c95eb732a6382bfd1", 16),
        				new BigInteger("7c2b0698a5afa2e837198c8c6d2484cc6f5270e75a2d7223cdf7ec1869617c6819f1d56bdf13f71a27a2a46aacdb68a5acda4ab7d7070883d05fbb385a71dd0846d4eb7880a82cac0c49bf861746c5d60127efa07355d354dd6e7580a12cc8ae3b3bdbf1e47934b680d3ce3dc229c0ae686ed33045f28dde6c0c3fba17f2c829", 16),
        				new BigInteger("912e62accdfe30d6ccb3298f6793a6441a5190f28a2e421662a6b75350a78ec809c2e19cd509d66c814629d78931a46b8d9958890c65a9be40e3f00c4fdd28739378162e478d478c1758480377793fdaa4310873788a5d7017f8f4136d02ad0174236105c9e91aaa55aa1459e319320dc4e95f5da1d3b4996a7d764332a5a031", 16),
        				new BigInteger("68ce96ef2e325ac041ce414a64a9dc74b089b556669cb932bf3356fdba6d7947d1a55b5e13ab7ecb376fecf504d38f882d396d5c3ace2b718669919f3fa293c1d4d4c53850b74242d19b3c3193293f1a70d39a08ae3e6a7eb28dd51115eede0ee4cb77103bf5da73876f560d22245fe69940eb472aa5fc57770f462c860d7610", 16)),
        			new RSAPublicKeySpec(
        				new BigInteger("84d4269505c38ba8c5fee8619cf0442eb55c31ae76ec430c1bbe3c82e48a1b56c6f2a3449edf044bcb7151b5df289182b685456f60f819ff7307478fe24f322c6afd4beae7bb4ad50c8bb26c9d0bd505cd91afb144003bea1d2c7fd743178d0141789aca69a5a97918dfccf7d82b25b1bf952cf06f9f432b338ddb773f79583dbbbeaf9fc4cf0878154fdcdfff160b3b5c1ed713990264ab97a3c0a5c617fe123395c03bf94ab24e3f7120ab7d95d06aa83ec9481566b1b6c2dcc9047a46abbf8ee43b32b5589edca36b3342073eb6bf8838a397363bf567640c1d0536961c125b81c0d31d09bd08171b1b6ca9343e09cfa7e3a6010e98d46da7cb6adccf52d5", 16),
        				new BigInteger("10001", 16)));
			*/
    		PKCS10CertificationRequestBuilder crb = new JcaPKCS10CertificationRequestBuilder(
    				new X500Name(clientSubject), clientCert.getPublicKey());

    		DERPrintableString password = new DERPrintableString("secret");
    		crb.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, password);
  		
    		ExtensionsGenerator extGen = new ExtensionsGenerator();
    		extGen.addExtension(X509Extension.subjectAlternativeName,
                    false, new GeneralNames(
                               new GeneralName(
                                   GeneralName.rfc822Name,
                                   "feedback-crypto@bouncycastle.org")));
    		
    		crb.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    extGen.generate());

    		ContentSigner cs = new JcaContentSignerBuilder("SHA1withRSA")
    				.setProvider(BC).build(clientKeys.getPrivateKey());
    		PKCS10CertificationRequest csr = crb.build(cs);
    		
    		//server.setAttribute(MdmScepServlet.SESSION_PASSWD, "secret");
    		
    		// Send the enrollment request
    		//LOG.debug("\n-------------------------------------------------------------------------");
    		EnrollmentResponse resp = client.enrol(clientCert, clientKeys.getPrivateKey(), csr);		
    		assertTrue(resp.isSuccess());
    		CertStore store = resp.getCertStore();
    		
    		DefaultCertStoreInspectorFactory inspectFactory = new DefaultCertStoreInspectorFactory();
    		CertStoreInspector inspector = inspectFactory.getInstance(store);
    		
    		X509Certificate CLIENT_RESULT = inspector.getRecipient();
    		X509Certificate CA_RESULT = inspector.getIssuer(); 
    		
    		CLIENT_RESULT.verify(CA_RESULT.getPublicKey());
        	CA_RESULT.verify(caCert.getPublicKey());

        	CLIENT_RESULT.verify(caCert.getPublicKey());
        } catch (Exception e) {
        	e.printStackTrace();
        	fail();
        }
	}
}
