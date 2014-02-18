package com.mdm.api.test;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import static org.easymock.EasyMock.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.mdm.api.EnrollStatusResponseData;
import com.mdm.api.EnrollmentHolder;
import com.mdm.api.EnrollmentManager;
import com.mdm.auth.PasscodeGenerator;
import com.mdm.auth.PasscodeGenerator.IntervalClock;
import com.mdm.cert.CertificateAuthority;
import com.mdm.cert.CertificateAuthorityException;
import com.mdm.cert.ICertificateAuthorityConnector;
import com.mdm.cert.ICertificateAuthorityStore;
import com.mdm.cert.X509CertificateGenerator;
import com.mdm.session.UrlRewriteFilter;
import com.mdm.utils.MdmServiceProperties;
import com.mdm.cert.RSAKeyPair;

public class EnrollmentHolderTest {
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	private static final int INTERVAL_PERIOD = 20;
	private static final int VALIDITY_PERIOD = 10;
	private String parentId = null;
	private X509Certificate caCert;
	private PrivateKey caPriv;
	private X509Certificate raCert;
	private PrivateKey raPriv;
	
	public static class MockClock implements IntervalClock {
		private long time;
		public MockClock() {
			time = 0;
		}
		@Override
		public long getTime() {
			return time;
		}
		public void tick(long t) {
			time += t;
		}
	}
	
	public static class MockConnector implements ICertificateAuthorityConnector {

		long counter = 10;
		@Override
		public ICertificateAuthorityStore getStoreInstance() {
			fail();
			return null;
		}

		@Override
		public String getObjectId() {
			fail();
			return null;
		}

		@Override
		public void addCaCRL(Date notBefore, Date notafter, X509CRL crl) {
			fail();
		}

		@Override
		public X509CRL getCaCRL() {
			fail();
			return null;
		}

		@Override
		public X509CRL getIssuedCRL() {
			fail();
			return null;
		}

		@Override
		public boolean isEnabled() {
			return true;
		}

		@Override
		public void setEnabled(boolean enableState) {
		}

		@Override
		public long getNextSerialNumber() throws CertificateAuthorityException {
			return counter++;
		}
	}

	public EnrollmentHolderTest() {
	}
	
	@Before
	public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
		try {
			PublicKey caPub, raPub;
	        KeyFactory fact = KeyFactory.getInstance("RSA", BC);
			MdmServiceProperties.Initialize();
			parentId = "P" + Long.toString(Calendar.getInstance().getTimeInMillis(), 32);
	
			caPriv = fact.generatePrivate(new RSAPrivateCrtKeySpec(
						new BigInteger("b19fda976e289cbb25c3885f106ec021f09cdb826e7ee64ede7bf93e6ff1d87ffa92b0d7bd0cf9f7d99762ce4ba235e6ec8ee601ffe3b1d669f4835ece0aeba609055b55219e06e09b0312754c0a3d2cd24f50ce885fca56737e1a0cf965cdfd82705da658d2940fbf3557aecff6cfc9809871ac0d323585c732213ae66b33b1", 16),
						new BigInteger("10001", 16),
						new BigInteger("9b5673326f7230ef322d783bbb014021ee6d1f434822ce8336eb30a43bfe431a5926a46567bdcb75c7e32ed3bf2d52fa6af2e58fe61b58d16cc41b8773a5f5423cac86ad73498855e0e0251e4cddfcfcf7a8093bb79833407bcabf6d689ed8306b6acf58dc6b7032c4215ab70cdd041ae66df65adef97c9f4d132f6aaee34769", 16),
						new BigInteger("f4a6479e90ddd9d4c37eafe0ade8114fd2942315f40f209e9c3e9fcc51861f31ef830f7979058354557d4fcedcf0f001d88532337429e0573743e11372ec3533", 16),
						new BigInteger("b9dd831a14f9e77ea0ef557b7f5b6f20580391d3fb9c4e4f637e914efe4f8a90b4a2b34f5dd4759666ac0e72a72710d52dd8bfe1fc7c19b7fbd30083a65a6b8b", 16),
						new BigInteger("158bff8acb9f7e6beabbe1a99c27703ee38100861274b29ec58c0e6ee44f37b8222c1cd4c9ffde4d332a523919e46e7efb1ee009001620180e5a001cc2666359", 16),
						new BigInteger("601fe5bbc9796d7619f96d764f6994515ff388a9df88f91f29cfbd8ae30f74145eb77e90df700fd8570548fb96e3275b79388e146c262a8ef2982fbde67d00fd", 16),
						new BigInteger("99f7163d85cf89036227a989ceaecc08ae830ab3a33c556d4496046bebef67f43524c5c06d4e66579b68a71600cdcfc34265d2ca27700456932a524f310a2d0f", 16)));
	    	caPub = fact.generatePublic(
					new RSAPublicKeySpec(
						new BigInteger("b19fda976e289cbb25c3885f106ec021f09cdb826e7ee64ede7bf93e6ff1d87ffa92b0d7bd0cf9f7d99762ce4ba235e6ec8ee601ffe3b1d669f4835ece0aeba609055b55219e06e09b0312754c0a3d2cd24f50ce885fca56737e1a0cf965cdfd82705da658d2940fbf3557aecff6cfc9809871ac0d323585c732213ae66b33b1", 16),
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
	    	
			// Create self signed CA
	        caCert = X509CertificateGenerator.createV3RootCA(
	        		caPub,
	        		caPriv,
	        		1,
	        		2,
	        		"CN=" + parentId + ", C=US, ST=California, L=Woodside ,O=Acme Inc,OU=Root Certificate", 
	        		null, null);	// set issuer=subject
	        raCert = X509CertificateGenerator.createCert(
	        		raPub,
	        		caCert,
	        		caPriv,
	        		2, caCert.getNotAfter(),
	        		"CN=Pablobill, C=US, ST=California, L=Woodside,O=Acme Inc.,OU=EndEntity Certificate",
	        		null, null);
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@After
	public void tearDown() throws Exception {
		Security.removeProvider(BC); 
	}
	
	// Test Helper
	private PKCS10CertificationRequest createCSR(PublicKey pubKey, PrivateKey privKey, String subject) throws Exception {
		PKCS10CertificationRequestBuilder crb = new JcaPKCS10CertificationRequestBuilder(
				new X500Name(subject), pubKey);

		DERPrintableString password = new DERPrintableString("secret");
		crb.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, password);
		
		/*
		ExtensionsGenerator extGen = new ExtensionsGenerator();
		extGen.addExtension(X509Extension.subjectAlternativeName,
                false, new GeneralNames(
                           new GeneralName(
                               GeneralName.rfc822Name,
                               "feedback-crypto@bouncycastle.org")));
		
		crb.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                extGen.generate());
        */

		ContentSigner cs = new JcaContentSignerBuilder("SHA1withRSA")
				.setProvider(BC).build(privKey);
		return crb.build(cs);		
	}
	
	// Test Helper
	private X509Certificate fulfillCSR(PKCS10CertificationRequest csr, X509Certificate caCert, PrivateKey caPrivKey, long serialNum) throws Exception {

		X509CertificateHolder caHolder = new JcaX509CertificateHolder(caCert);
        X500Name subject = X500Name.getInstance(csr.getSubject());
        X500Name issuer = X500Name.getInstance(caHolder.getSubject());
		SubjectPublicKeyInfo subjectKeyId = csr.getSubjectPublicKeyInfo();
	    Calendar cal = GregorianCalendar.getInstance();
	    cal.set(Calendar.MILLISECOND, 0);
	    cal.set(Calendar.SECOND, 0);
	    cal.add(Calendar.MINUTE, -1);
	    Date notBefore = cal.getTime();
	    cal.add(Calendar.YEAR, 5);
	    Date notAfter = cal.getTime();
	    if (notAfter.after(caCert.getNotAfter()))
	    	notAfter = caCert.getNotAfter();
	    
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, BigInteger.valueOf(serialNum), notBefore, notAfter, subject, subjectKeyId);
    
        BcX509ExtensionUtils extUtils = new BcX509ExtensionUtils();
	    builder.addExtension(X509Extension.basicConstraints, false, new BasicConstraints(false));	    
	    builder.addExtension(X509Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectKeyId));
	    builder.addExtension(X509Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caHolder));
	    builder.addExtension(X509Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature|KeyUsage.keyEncipherment));
	    
	    ContentSigner signer;
	    try {
			AsymmetricKeyParameter priv = PrivateKeyFactory.createKey(caPrivKey.getEncoded());
	        AlgorithmIdentifier sigAlg = csr.getSignatureAlgorithm();
	        AlgorithmIdentifier digAlg = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlg);
	        signer = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(priv);     
	        
	    } catch (OperatorCreationException e) {
	        throw new Exception(e);
	    }
	    X509CertificateHolder holder = builder.build(signer);
	    X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
	    cert.checkValidity(new Date());
	    cert.verify(caCert.getPublicKey());
	    return cert;
	}
	
	@Test
	public void testEnrollChild() throws NoSuchAlgorithmException {
		
		String enrollId = "C" + Long.toString(Calendar.getInstance().getTimeInMillis(), 32);
		EnrollmentHolder eholder = null;
		PasscodeGenerator gen = null;
		CertificateAuthority ca = new CertificateAuthority(new MockConnector(), caCert, raCert, raPriv);
		MockClock clock = new MockClock();
		try {
			gen = createMockBuilder(PasscodeGenerator.class)
					.withConstructor(EnrollmentManager.getTimecodeSigner(parentId),
							-1, INTERVAL_PERIOD, VALIDITY_PERIOD)
					.addMockedMethod("getClock")
					.createMock();
			expect(gen.getClock()).andReturn(clock);
			replay();
	
	        eholder = new EnrollmentHolder(parentId, ca, enrollId, 
	    			100, 101, "http://localhost/enroll", gen);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		
        EnrollStatusResponseData status = eholder.getEnrollStatus();
        assertTrue(status.getNextUpdate() == INTERVAL_PERIOD);
        String lastOTP = status.getOTP();
        assertTrue(lastOTP != null);
        
        clock.tick(INTERVAL_PERIOD - VALIDITY_PERIOD/2);
        status = eholder.getEnrollStatus();
        assertTrue(status.getNextUpdate() == VALIDITY_PERIOD/2);
        assertTrue(status.getOTP().equals(lastOTP));
        
        clock.tick(VALIDITY_PERIOD);
        status = eholder.getEnrollStatus();
        assertTrue(status.getNextUpdate() == (INTERVAL_PERIOD - VALIDITY_PERIOD/2));
        assertTrue(status.getOTP().equals(lastOTP));
        
        clock.tick(INTERVAL_PERIOD);
        status = eholder.getEnrollStatus();
        assertTrue(status.getNextUpdate() == (INTERVAL_PERIOD - VALIDITY_PERIOD/2));
        assertFalse(status.getOTP().equals(lastOTP));
        
        assertTrue(parentId == eholder.getParentId());
        assertTrue(eholder.getAuthorizedOTP() == null);
        assertTrue(eholder.getSerialNums().length == 2);
        assertTrue(eholder.getSerialNums()[0] > 0);
        assertTrue(eholder.getSerialNums()[1] > 0);
        assertTrue(status.getActionCode() == 0);
        assertTrue(status.getNextUpdate() > 0);
         
        boolean result = false;
        try {
            result = eholder.authorize(status.getOTP());
		} catch (Exception e) {
			fail();
		}
        assertTrue(result);
        assertTrue(eholder.isAuthorized());
        status = eholder.getEnrollStatus();
        assertTrue(status.getActionCode() == 0);
        
        RSAKeyPair ourKeys = new RSAKeyPair();
    	try {
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
		} catch (Exception e) {
			fail();
		}
    	
    	try {
    		PKCS10CertificationRequest csr = createCSR(ourKeys.getPublicKey(), ourKeys.getPrivateKey(), "CN=ScepClient, O=Mdm Client, OU=Unit Test, C=US, ST=California, L=Woodside");
	    	eholder.scepInitiateCSR(csr);
		} catch (Exception e) {
			fail();
		}
    	assertTrue(eholder.isWaitingCSR());
    	status = eholder.getEnrollStatus();
    	assertTrue(status.getActionCode() == EnrollStatusResponseData.DO_CSR);
    	
    	try {
			X509Certificate deviceCert = fulfillCSR(eholder.getCSR(), caCert, caPriv, eholder.getSerialNums()[0]);
			eholder.completeCSR(deviceCert);
		} catch (Exception e) {
			fail();
		}
    	assertTrue(eholder.isCompletedCSR());	// done device CSR
    	
    	try {
        	eholder.scepCloseCSR();    		
		} catch (Exception e) {
			fail();
		}
    	assertTrue(eholder.isDeviceEnrolled());
    	
    	try {
    		PKCS10CertificationRequest csr = createCSR(ourKeys.getPublicKey(), ourKeys.getPrivateKey(), "CN=ScepClient, O=Mdm Client, OU=Unit Test, C=US, ST=California, L=Woodside");
	    	eholder.clientInitiateCSR(csr);
		} catch (Exception e) {
			fail();
		}
    	assertTrue(eholder.isDeviceEnrolled());
    	assertTrue(eholder.isWaitingCSR());
    	status = eholder.getEnrollStatus();
    	assertTrue(status.getActionCode() == EnrollStatusResponseData.DO_CSR);
    	assertTrue(eholder.getSerialNums()[0] == 0);
    	assertTrue(eholder.getSerialNums()[1] != 0);
    	
    	try {
			X509Certificate clientCert = fulfillCSR(eholder.getCSR(), caCert, caPriv, eholder.getSerialNums()[1]);
			eholder.completeCSR(clientCert);
		} catch (Exception e) {
			fail();
		}
    	assertTrue(eholder.isDeviceEnrolled());
    	assertTrue(eholder.isCompletedCSR());	// done device CSR 
    	assertTrue(eholder.getSerialNums()[0] == 0);
    	assertTrue(eholder.getSerialNums()[1] == 0);
    	try {
        	eholder.clientCloseCSR();    		
		} catch (Exception e) {
			fail();
		}
    	assertTrue(eholder.isDeviceEnrolled());
    	assertTrue(eholder.isEnrolled());
    	verify();
	}
}
