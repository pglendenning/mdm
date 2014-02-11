/**
 * 
 */
package com.mdm.cert.test;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Calendar;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.mdm.cert.AwsCertificateAuthorityStore;
import com.mdm.cert.CertificateAuthority;
import com.mdm.cert.CertificateAuthorityException;
import com.mdm.cert.IssuedCertificateResult;
import com.mdm.cert.IssuerAndSerialNumberHolder;
import com.mdm.cert.X509CertificateGenerator;
import com.mdm.utils.MdmServiceProperties;

/**
 * @author paul
 *
 */
public class AwsCertificateAuthorityStoreTest {

	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	
	public X509Certificate caCert = null;
	public PrivateKey caPriv = null;
	public PublicKey  caPub = null;
	public X509Certificate raCert = null;
	public PrivateKey raPriv = null;
	public PublicKey  raPub = null;
	public X509Certificate issuedCert1 = null;
	public PrivateKey issuedPriv1 = null;
	public PublicKey  issuedPub1 = null;
	public X509Certificate issuedCert2 = null;
	public PrivateKey issuedPriv2 = null;
	public PublicKey  issuedPub2 = null;
	public String objectId = Long.toString(Calendar.getInstance().getTimeInMillis(), 32);
	public IssuerAndSerialNumber caIasn = null;

	@Before
	public void setUp() {
        Security.addProvider(new BouncyCastleProvider());		
    	try {
    		 KeyFactory fact = KeyFactory.getInstance("RSA", BC);
    		 MdmServiceProperties.Initialize();
		   	 
   			caPriv = fact.generatePrivate(new RSAPrivateCrtKeySpec(
    				new BigInteger("84d4269505c38ba8c5fee8619cf0442eb55c31ae76ec430c1bbe3c82e48a1b56c6f2a3449edf044bcb7151b5df289182b685456f60f819ff7307478fe24f322c6afd4beae7bb4ad50c8bb26c9d0bd505cd91afb144003bea1d2c7fd743178d0141789aca69a5a97918dfccf7d82b25b1bf952cf06f9f432b338ddb773f79583dbbbeaf9fc4cf0878154fdcdfff160b3b5c1ed713990264ab97a3c0a5c617fe123395c03bf94ab24e3f7120ab7d95d06aa83ec9481566b1b6c2dcc9047a46abbf8ee43b32b5589edca36b3342073eb6bf8838a397363bf567640c1d0536961c125b81c0d31d09bd08171b1b6ca9343e09cfa7e3a6010e98d46da7cb6adccf52d5", 16),
    				new BigInteger("10001", 16),
    				new BigInteger("341584337719205043a31ab7fbf3f2a866110aa2209bb006b5723904125d5d2effbff0e95d6a91a2aed97672dc586a06594f94d481af87723546ab76ee04a3e5eae5fbb8d6b90834d64088ec32008bbd44c8559e2acdf4b06e541ea4e7f7fa207dedaeb4a40c8391aa81473c00159b2841b95aefc4b52c7f6a2dbbdadc96d6547dfd74b25ccddfcf3bdea3175322e70bb99f8d56e4c5daccfb551bb8ab25755d0f7ab17ecc8b426e7757eeedc19fc4e06270268da33a14d398aeeb745ae1f06ed8fadf51b46390edb5cd4feb042757886bf2d0a4dde903c8ae92aaea9580726ee0a8ce16abc9c176332db1f48a6bf238d3400d446099f67e7c1180600d0b4e81", 16),
    				new BigInteger("bc7766d15d55cb9c67d691028f39a7185e61d43524411a091573059c5ae3df2fd0272cb9e9354a598503c25ed8d27065406666f67d0bf02cbbb52c9f2a9e58e02f39a7a4b7fdb51b5ca1f43659760736d636628a96c04184d93575fe1238db941dcca684d5a66eba2d925b3e6f2728e618dc87e2d6195ff2aedf4e742e8307c5", 16),
    				new BigInteger("b46ceef3b9ef7fb60b7ec40b9914b19d230af1789ad77da6b0f350afa75a214a38f4fdecfe3b3b45101d7dcd491e66d046a08728e9bee97d4d33905445e4573f78c0c9d23620067e01b864c20a3f135aad3c163769e3ba3e5e043e3773f304ed8b460f73db32a3c1f62ab826224c133300345f0ba6d2018c95eb732a6382bfd1", 16),
    				new BigInteger("7c2b0698a5afa2e837198c8c6d2484cc6f5270e75a2d7223cdf7ec1869617c6819f1d56bdf13f71a27a2a46aacdb68a5acda4ab7d7070883d05fbb385a71dd0846d4eb7880a82cac0c49bf861746c5d60127efa07355d354dd6e7580a12cc8ae3b3bdbf1e47934b680d3ce3dc229c0ae686ed33045f28dde6c0c3fba17f2c829", 16),
    				new BigInteger("912e62accdfe30d6ccb3298f6793a6441a5190f28a2e421662a6b75350a78ec809c2e19cd509d66c814629d78931a46b8d9958890c65a9be40e3f00c4fdd28739378162e478d478c1758480377793fdaa4310873788a5d7017f8f4136d02ad0174236105c9e91aaa55aa1459e319320dc4e95f5da1d3b4996a7d764332a5a031", 16),
    				new BigInteger("68ce96ef2e325ac041ce414a64a9dc74b089b556669cb932bf3356fdba6d7947d1a55b5e13ab7ecb376fecf504d38f882d396d5c3ace2b718669919f3fa293c1d4d4c53850b74242d19b3c3193293f1a70d39a08ae3e6a7eb28dd51115eede0ee4cb77103bf5da73876f560d22245fe69940eb472aa5fc57770f462c860d7610", 16)));
	    	caPub = fact.generatePublic(
	    			new RSAPublicKeySpec(
	    				new BigInteger("84d4269505c38ba8c5fee8619cf0442eb55c31ae76ec430c1bbe3c82e48a1b56c6f2a3449edf044bcb7151b5df289182b685456f60f819ff7307478fe24f322c6afd4beae7bb4ad50c8bb26c9d0bd505cd91afb144003bea1d2c7fd743178d0141789aca69a5a97918dfccf7d82b25b1bf952cf06f9f432b338ddb773f79583dbbbeaf9fc4cf0878154fdcdfff160b3b5c1ed713990264ab97a3c0a5c617fe123395c03bf94ab24e3f7120ab7d95d06aa83ec9481566b1b6c2dcc9047a46abbf8ee43b32b5589edca36b3342073eb6bf8838a397363bf567640c1d0536961c125b81c0d31d09bd08171b1b6ca9343e09cfa7e3a6010e98d46da7cb6adccf52d5", 16),
	    				new BigInteger("10001", 16)));

	    	raPriv = fact.generatePrivate(
	    			new RSAPrivateCrtKeySpec(
	    				new BigInteger("a5226e241a19f5b796ef2326f4f580b1e5cbc05360a7fd94fd8d59013115e077a422beb4904c5e57f0d9827a0da98b337ab8d47a2b24f77d83f9689e9b43af6b23bf39a1e4e87d8ce9f7d68b8dd50ffec1d34b25833848325ed035d3a1ddeaf62fe5a184dec918d7c2e8b89b17b057a9af359280956dc2a393be6e9a04517b25", 16),
	    				new BigInteger("10001", 16),
	    				new BigInteger("6ff223507e11532e1e380750858758b340e11b846a65f7d664fcc975b15cef4aac0e91d1be70c7143ec6755960a1ab283eedc5bcfc3a973c9397248141286565d479dd57d9bc01d4dec645dd1ae01590671315ec6f9bcde606707255382fcb363744a8bcda3c7a3c2e4015d450ed4aafb675ae277ddcf0e779165125a84f6681", 16),
	    				new BigInteger("f8e745cf5388418a0f038b425095aa8ce3cae42764c15d6f91021a0b6fe0746653428ac95c88ce127deae745521805b6a53da780b56c3f4d15f0c88a85a19609", 16),
	    				new BigInteger("a9d7bc0903893d8116ad8df22e425df382f895d47c0a47d7ea182e9a6221f3d1b27cdfd278960d8cc65699a5c1e5e17197805c9954ff6c37c19a0d9e2241a33d", 16),
	    				new BigInteger("88181ca9a228ec7d0a7c8b9674ed80d58c701194209941f790b82f797570aaf4902de028fdb9a7c3a0a9e24e9af69b99247cb3abc2872f8d7ca3ad636071dbd1", 16),
	    				new BigInteger("5f024cb0aa26ba9e1cc68772238882aff6e30245b401b840c33635d3acf39b4601d7b30934e593bcdd32928ed411b97466b0aa9c279d1eb76df8b48772584f6d", 16),
	    				new BigInteger("e9774efb165c4309e7c7f32603d882d2e8b728887ddb50ee2c2e89591d192b64058699d3251e01348ee24dd23669aec43f1b4e16266950f6268e632242b7d500", 16)));
	    	raPub = fact.generatePublic(
	    			new RSAPublicKeySpec(
	    				new BigInteger("a5226e241a19f5b796ef2326f4f580b1e5cbc05360a7fd94fd8d59013115e077a422beb4904c5e57f0d9827a0da98b337ab8d47a2b24f77d83f9689e9b43af6b23bf39a1e4e87d8ce9f7d68b8dd50ffec1d34b25833848325ed035d3a1ddeaf62fe5a184dec918d7c2e8b89b17b057a9af359280956dc2a393be6e9a04517b25", 16),
	    				new BigInteger("10001", 16)));
	    	
    		issuedPriv1 = fact.generatePrivate(new RSAPrivateCrtKeySpec(
						new BigInteger("b19fda976e289cbb25c3885f106ec021f09cdb826e7ee64ede7bf93e6ff1d87ffa92b0d7bd0cf9f7d99762ce4ba235e6ec8ee601ffe3b1d669f4835ece0aeba609055b55219e06e09b0312754c0a3d2cd24f50ce885fca56737e1a0cf965cdfd82705da658d2940fbf3557aecff6cfc9809871ac0d323585c732213ae66b33b1", 16),
						new BigInteger("10001", 16),
						new BigInteger("9b5673326f7230ef322d783bbb014021ee6d1f434822ce8336eb30a43bfe431a5926a46567bdcb75c7e32ed3bf2d52fa6af2e58fe61b58d16cc41b8773a5f5423cac86ad73498855e0e0251e4cddfcfcf7a8093bb79833407bcabf6d689ed8306b6acf58dc6b7032c4215ab70cdd041ae66df65adef97c9f4d132f6aaee34769", 16),
						new BigInteger("f4a6479e90ddd9d4c37eafe0ade8114fd2942315f40f209e9c3e9fcc51861f31ef830f7979058354557d4fcedcf0f001d88532337429e0573743e11372ec3533", 16),
						new BigInteger("b9dd831a14f9e77ea0ef557b7f5b6f20580391d3fb9c4e4f637e914efe4f8a90b4a2b34f5dd4759666ac0e72a72710d52dd8bfe1fc7c19b7fbd30083a65a6b8b", 16),
						new BigInteger("158bff8acb9f7e6beabbe1a99c27703ee38100861274b29ec58c0e6ee44f37b8222c1cd4c9ffde4d332a523919e46e7efb1ee009001620180e5a001cc2666359", 16),
						new BigInteger("601fe5bbc9796d7619f96d764f6994515ff388a9df88f91f29cfbd8ae30f74145eb77e90df700fd8570548fb96e3275b79388e146c262a8ef2982fbde67d00fd", 16),
						new BigInteger("99f7163d85cf89036227a989ceaecc08ae830ab3a33c556d4496046bebef67f43524c5c06d4e66579b68a71600cdcfc34265d2ca27700456932a524f310a2d0f", 16)));
	    	issuedPub1 = fact.generatePublic(
					new RSAPublicKeySpec(
						new BigInteger("b19fda976e289cbb25c3885f106ec021f09cdb826e7ee64ede7bf93e6ff1d87ffa92b0d7bd0cf9f7d99762ce4ba235e6ec8ee601ffe3b1d669f4835ece0aeba609055b55219e06e09b0312754c0a3d2cd24f50ce885fca56737e1a0cf965cdfd82705da658d2940fbf3557aecff6cfc9809871ac0d323585c732213ae66b33b1", 16),
						new BigInteger("10001", 16)));
	    	
   			issuedPriv2 = fact.generatePrivate(new RSAPrivateCrtKeySpec(
					new BigInteger("b447bdace3bc4f20f18b7261e74183b13b8db967ba040ab78b0824ba1b1cbd3aa4b2c5a3d13835da2e4b575074605598a62464f49ccd51b4b420cdaacf7a1dc8f3a22c33efebfa2818f653de7c3d33500e815503138719af529f827ea00f9143652b8067cf4242cf3c705a7e0dc4a8391257a79a7ccc4efc78c9db85028c6e69", 16),
					new BigInteger("10001", 16),
					new BigInteger("128a5e436d986c3ae31c8842f15997859eae50a70e466423c434ae32459f8b0680f1b1c9cb3690b3439793ff3e38ba14dce159509edfaecb7acaf4dbe0429ad5672f67a1baf8c52165f9033821e4022e4fd52545dfb7493e5ffd8180c05e9867a86ea7eeb49ace1cec72bc37dfca1586a2b613b6f9f1ae0819e9d1dd732fd391", 16),
					new BigInteger("f8b4b3311888e1ebe222c31d1aa266f0d49dbdbc58407d5406a325033b75b99bc658544a5eaade4b3dc5e6bd6a7d1379aa6d8589a16da822a97703a6fd04e40f", 16),
					new BigInteger("b9914bff3f83e84b97d13dc2402ccc9673a47f9cd66d50efd617f5a1000c84eb8033068970d67de5e43e40e8bf28fe4f93cb80d453853e1aaf7f5de56d18ae07", 16),
					new BigInteger("a9ddf1ce04ade970cd21651689cc8676d32172282436d7e2fe2d8be82b427b2574517c30d77be91c86f29668a5450c7a3af7570febdc13cca8e68aee113eb7ed", 16),
					new BigInteger("6be70ce5d32d047a50411f4440c4cc0200247affdbbf9cfc98e53db2ecb05aea0595a60b6d4d8bcf8db49551c136390a54ca5493222dac3b2029539400a80529", 16),
					new BigInteger("970d0c849535a9f51544f2b8baa5bdc2aecf90ca37561070c5aebac4eb59be510066c85a1d4d9c610353826347accdf21758663cb0e7d05f2bcae31c7c3f2915", 16)));
	    	issuedPub2 = fact.generatePublic(
				new RSAPublicKeySpec(
					new BigInteger("b447bdace3bc4f20f18b7261e74183b13b8db967ba040ab78b0824ba1b1cbd3aa4b2c5a3d13835da2e4b575074605598a62464f49ccd51b4b420cdaacf7a1dc8f3a22c33efebfa2818f653de7c3d33500e815503138719af529f827ea00f9143652b8067cf4242cf3c705a7e0dc4a8391257a79a7ccc4efc78c9db85028c6e69", 16),
					new BigInteger("10001", 16)));
		
			// Create self signed CA
	        caCert = X509CertificateGenerator.createV3RootCA(
	        		caPub,
	        		caPriv,
	        		1,
	        		2,
	        		"CN=" + objectId + ", C=US, ST=California, L=Woodside ,O=Acme Inc,OU=Root Certificate", 
	        		null, null);	// set issuer=subject
	        raCert = X509CertificateGenerator.createCert(
	        		raPub,
	        		caCert,
	        		caPriv,
	        		2, caCert.getNotAfter(),
	        		"CN=Pablobill, C=US, ST=California, L=Woodside,O=Acme Inc.,OU=EndEntity Certificate",
	        		null, null);
	        issuedCert1 = X509CertificateGenerator.createCert(
	        		issuedPub1,
	        		caCert,
	        		caPriv,
	        		3, caCert.getNotAfter(),
	        		"CN=Pablobill, C=US, ST=California, L=Woodside,O=Acme Inc.,OU=EndEntity Certificate",
	        		null, null);
	        issuedCert2 = X509CertificateGenerator.createCert(
	        		issuedPub2,
	        		caCert,
	        		caPriv,
	        		4, caCert.getNotAfter(),
	        		"CN=Pablobill, C=US, ST=California, L=Woodside,O=Acme Inc.,OU=EndEntity Certificate",
	        		null, null);
	        
			caIasn = new IssuerAndSerialNumberHolder(caCert).getIasn();
	        
		} catch (Exception e) {
			fail();
		}
	}
	
	@After
	public void tearDown() throws Exception {
		Security.removeProvider(BC); 
	}
	
	@Test 
	public void testCA() {
		objectId = Long.toString(Calendar.getInstance().getTimeInMillis(), 32) + "A";
		testAddCA();
		testGetCAIssuerAndSerialNumber();
		testGetCAString();
		testGetNextSerialNumber();
		testRemoveCA();
	}
	
	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#addCA(java.security.cert.X509Certificate, org.bouncycastle.asn1.cms.IssuerAndSerialNumber, java.security.cert.X509Certificate, java.security.PrivateKey, long, boolean, java.lang.String)}.
	 */
	public void testAddCA() {
		AwsCertificateAuthorityStore store = new AwsCertificateAuthorityStore();
		
		// Test addCA
		try {
			store.addCA(caCert, raCert, raPriv, 3, true, objectId);
		} catch (Exception e) {
			fail("Exception: " + e.getMessage());
		}
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#getCA(org.bouncycastle.asn1.cms.IssuerAndSerialNumber)}.
	 */
	public void testGetCAIssuerAndSerialNumber() {
		// Test getCA from issuer and serial number
		AwsCertificateAuthorityStore store = new AwsCertificateAuthorityStore();
		CertificateAuthority ca = null;
		try {
			CertificateAuthority _ca = store.getCA(caIasn);
			ca = _ca;
		} catch (Exception e) {
			fail("Exception: " + e.getMessage());
		}
		assertFalse(ca == null);
		assertTrue(ca.getObjectId().equals(objectId));
		try {
			ca.getRaCertificate().verify(caPub);
			ca.getCaCertificate().verify(caPub);
		} catch (Exception e) {
			fail("Exception: " + e.getMessage());
		}
		
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#getCA(java.lang.String)}.
	 */
	public void testGetCAString() {
		// Test getCA given objectId
		AwsCertificateAuthorityStore store = new AwsCertificateAuthorityStore();
		CertificateAuthority ca = null;
		try {
			CertificateAuthority _ca = store.getCA(objectId);
			ca = _ca;
		} catch (Exception e) {
			fail("Exception: " + e.getMessage());
		}
		assertFalse(ca == null);
		assertTrue(ca.getObjectId().equals(objectId));
		try {
			ca.getRaCertificate().verify(caPub);
			ca.getCaCertificate().verify(caPub);
		} catch (Exception e) {
			fail("Exception: " + e.getMessage());
		}
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#getNextSerialNumber(java.lang.String)}.
	 */
	public void testGetNextSerialNumber() {
		AwsCertificateAuthorityStore store = new AwsCertificateAuthorityStore();
		for (long i=3; i<10; ++i) {
			long j = 0;
			try {
				long k = store.getNextSerialNumber(objectId);
				j = k;
			} catch (CertificateAuthorityException e) {
				fail("Exception: " + e.getMessage());
			}
			assertTrue(j == i);
		}
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#removeCA(java.lang.String)}.
	 */
	public void testRemoveCA() {
		AwsCertificateAuthorityStore store = new AwsCertificateAuthorityStore();
		CertificateAuthority ca = null;
		try {
			CertificateAuthority _ca = store.getCA(objectId);
			ca = _ca;
			store.removeCA(objectId);
		} catch (Exception e) {
			fail("Exception: " + e.getMessage());
		}
		
		CertificateAuthority ca2 = ca;
		try {
			CertificateAuthority _ca = store.getCA(objectId);
			ca2 = _ca;
		} catch (Exception e) {
			ca2 = null; 
		}
		assertTrue(ca2 == null);
		
		try {
			CertificateAuthority _ca = store.getCA(caIasn);
			ca = _ca;
		} catch (Exception e) {
			ca = null;
		}
		assertTrue(ca == null);
	}
	
	@Test
	public void testIssued() {
		objectId = Long.toString(Calendar.getInstance().getTimeInMillis(), 32) + "B";
		testAddCA();
		testAddIssued();
		testGetDeviceIssuedIssuerAndSerialNumber();
		testGetDeviceIssuedString();
		testRemoveCA();
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#addIssued(java.security.cert.X509Certificate, org.bouncycastle.asn1.cms.IssuerAndSerialNumber, com.mdm.cert.IssuedCertificateIdentifier, java.lang.String, java.lang.String)}.
	 */
	public void testAddIssued() {
		AwsCertificateAuthorityStore store = new AwsCertificateAuthorityStore();
		CertificateAuthority ca = null;
		try {
			CertificateAuthority _ca = store.getCA(objectId);
			ca = _ca;
		} catch (Exception e) {
			fail("Exception: " + e.getMessage());
		}
		assertTrue(ca != null);
		try {
			store.addIssued(issuedCert1, null, objectId + "C1", objectId);
			store.addIssued(issuedCert2, null, objectId + "C2", objectId);
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#getDeviceIssued(org.bouncycastle.asn1.cms.IssuerAndSerialNumber)}.
	 */
	public void testGetDeviceIssuedIssuerAndSerialNumber() {
		AwsCertificateAuthorityStore store = new AwsCertificateAuthorityStore();
		CertificateAuthority ca = null;
		IssuedCertificateResult result = null;
		try {
			CertificateAuthority _ca = store.getCA(objectId);
			ca = _ca;
		} catch (Exception e) {
			fail("Exception: " + e.getMessage());
		}
		assertTrue(ca != null);
		IssuerAndSerialNumberHolder iasn = new IssuerAndSerialNumberHolder(issuedCert1);
		assertTrue(iasn.isValid());
		try {
			IssuedCertificateResult r1 = store.getDeviceIssued(iasn.getIasn());
			result = r1;
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
		assertTrue(result.getCa().getCaCertificate().equals(caCert));
		assertTrue(result.getIssuedCertificate().equals(issuedCert1));
		assertFalse(new IssuerAndSerialNumberHolder(result.getIssuedCertificate()).toString()
				.equals(new IssuerAndSerialNumberHolder(issuedCert2).toString()));
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#getDeviceIssued(java.lang.String)}.
	 */
	public void testGetDeviceIssuedString() {
		AwsCertificateAuthorityStore store = new AwsCertificateAuthorityStore();
		CertificateAuthority ca = null;
		IssuedCertificateResult result = null;
		try {
			CertificateAuthority _ca = store.getCA(objectId);
			ca = _ca;
		} catch (Exception e) {
			fail("Exception: " + e.getMessage());
		}
		assertTrue(ca != null);
		try {
			IssuedCertificateResult r1 = store.getDeviceIssued(objectId+"C2");
			result = r1;
		} catch (Exception e) {
			fail("Exception:" + e.getMessage());
		}
		assertTrue(result.getCa().getCaCertificate().equals(caCert));
		assertTrue(result.getIssuedCertificate().equals(issuedCert2));
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#getDeviceIssued(com.mdm.cert.IssuedCertificateIdentifier)}.
	 */
	public void testGetDeviceIssuedIssuedCertificateIdentifier() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#deleteIssued(java.lang.String)}.
	 */
	public void testDeleteIssued() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#setAppIssued(java.security.cert.X509Certificate, java.lang.String)}.
	 */
	public void testSetAppIssued() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#getCaCRL(java.lang.String, java.util.Date)}.
	 */
	public void testGetCaCRLStringDate() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#addCaCRL(java.lang.String, java.util.Date, java.util.Date, java.security.cert.X509CRL)}.
	 */
	public void testAddCaCRL() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#getCaCRL(java.lang.String)}.
	 */
	public void testGetCaCRLString() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#setCaEnabled(java.lang.String, boolean)}.
	 */
	public void testSetCaEnabled() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#getIssuedList(java.lang.String)}.
	 */
	public void testGetIssuedList() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link com.mdm.cert.AwsCertificateAuthorityStore#getIssuedCRL(java.lang.String)}.
	 */
	public void testGetIssuedCRL() {
		fail("Not yet implemented");
	}

}
