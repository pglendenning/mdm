package com.mdm.utils.test;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.NoSuchParserException;
import org.bouncycastle.x509.X509CollectionStoreParameters;
import org.bouncycastle.x509.X509Store;
import org.bouncycastle.x509.X509StreamParser;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.mdm.utils.PKCS7Signer;
import com.mdm.utils.RSAKeyPair;
import com.mdm.utils.X509CertificateGenerator;

public class PKCS7SignerTest {
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	
	private static byte[] signedDataWithoutCert1 = Base64.decode(
		  "MIIBhQYJKoZIhvcNAQcCoIIBdjCCAXICAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3"
		+ "DQEHATGCAVEwggFNAgEBMIGqMIGkMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs"
		+ "aWZvcm5pYTERMA8GA1UEBwwIV29vZHNpZGUxFDASBgNVBAoMC1NvbGlkcmEgTExD"
		+ "MR8wHQYDVQQLDBZJbmZvcm1hdGlvbiBUZWNobm9sb2d5MRQwEgYDVQQDDAsxOTIu"
		+ "MTY4LjEuNzEgMB4GCSqGSIb3DQEJARYRYWRtaW5Ac29saWRyYS5jb20CAQswCQYF"
		+ "Kw4DAhoFADANBgkqhkiG9w0BAQEFAASBgA+XPhn1YMR7YZsEy5eaeAs0nsKfg8ZO"
		+ "9NPa7vfbDZkgWK1GhcQq+rNxZdFm+AYWTgDyqBl/ShccpLJtXRnZreuW1El6fQUd"
		+ "HZvYmiNS/z3Od9/jqicR35Hkqmtm");
	
	private static byte[] cert = Base64.decode(
		  "MIID0DCCArigAwIBAgIBCzANBgkqhkiG9w0BAQUFADCBpDELMAkGA1UEBhMCVVMx"
		+ "EzARBgNVBAgMCkNhbGlmb3JuaWExETAPBgNVBAcMCFdvb2RzaWRlMRQwEgYDVQQK"
		+ "DAtTb2xpZHJhIExMQzEfMB0GA1UECwwWSW5mb3JtYXRpb24gVGVjaG5vbG9neTEU"
		+ "MBIGA1UEAwwLMTkyLjE2OC4xLjcxIDAeBgkqhkiG9w0BCQEWEWFkbWluQHNvbGlk"
		+ "cmEuY29tMB4XDTEzMDcyMjAzMTEwNFoXDTE0MDcyMjAzMTEwNFowgZExFDASBgNV"
		+ "BAMMCzE5Mi4xNjguMS43MRMwEQYDVQQIDApDYWxpZm9ybmlhMQswCQYDVQQGEwJV"
		+ "UzEgMB4GCSqGSIb3DQEJARYRYWRtaW5Ac29saWRyYS5jb20xFDASBgNVBAoMC1Nv"
		+ "bGlkcmEgTExDMR8wHQYDVQQLDBZJbmZvcm1hdGlvbiBUZWNobm9sb2d5MIGfMA0G"
		+ "CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRSN9IjCmfIneNsELBQkKJu7lj4pBKYw6a"
		+ "+abnoMrkA6zgnFjGrhBYLmX24HgKmvC6VXjbUK2JjJKUd52yaUXv5Ofw8ajXtn1+"
		+ "hKc7zijg5ctr5pGFEcNJ8KBu09trxsjmsqRE3VwEgHOlHFdl/bot+BAxkwJM4IbN"
		+ "jCDxSLcLcwIDAQABo4GhMIGeMAkGA1UdEwQCMAAwHQYDVR0OBBYEFK9mHdW0UfB6"
		+ "h1CBIYrPWwEakgZpMB8GA1UdIwQYMBaAFKKWlQeyaZxY/IfL2G4tSg8BLb4nMAsG"
		+ "A1UdDwQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAvBgNVHR8EKDAmMCSgIqAg"
		+ "hh5odHRwOi8vMTkyLjE2OC4xLjcvbWRtdGVzdC5jcmwwDQYJKoZIhvcNAQEFBQAD"
		+ "ggEBAK6YKXe/0IPlY1PUGVpXiuo0kRqmkXtOTcmNMCXlUEYnCTBLJpiaBE6T5meG"
		+ "V83LNc3I6Dnx0JwJtHLaZ0OCZwujPLhakK4Igu453jwGZX13PkgYyqcl70+bEB07"
		+ "PZiV0m0IwbSpE00b8higKYnycjJKTnj7SZ+hj9GBG+79x/mk8TOJA3JcwUq/osBb"
		+ "N93h5LzjCXk6fga6QYHHHDN9NCqi7IhLMxTzDPgw58B0rGiNcLIR7GkI/2rnBZ6c"
		+ "ahE5BlkSv6peUMzmeaiB7RE4WbicFnlpAJHCiYvYXunzDThpuH0NVcxWnDSD+TeI"
		+ "z9YyH5YsK1DzBnsYlQU2Xvu0E08=");
	
	private static  byte[] signedDataWithoutCert2 = Base64.decode(
		  "MIIBhQYJKoZIhvcNAQcCoIIBdjCCAXICAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3"
		+ "DQEHATGCAVEwggFNAgEBMIGqMIGkMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs"
		+ "aWZvcm5pYTERMA8GA1UEBwwIV29vZHNpZGUxFDASBgNVBAoMC1NvbGlkcmEgTExD"
		+ "MR8wHQYDVQQLDBZJbmZvcm1hdGlvbiBUZWNobm9sb2d5MRQwEgYDVQQDDAsxOTIu"
		+ "MTY4LjEuNzEgMB4GCSqGSIb3DQEJARYRYWRtaW5Ac29saWRyYS5jb20CAQswCQYF"
		+ "Kw4DAhoFADANBgkqhkiG9w0BAQEFAASBgA+XPhn1YMR7YZsEy5eaeAs0nsKfg8ZO"
		+ "9NPa7vfbDZkgWK1GhcQq+rNxZdFm+AYWTgDyqBl/ShccpLJtXRnZreuW1El6fQUd"
		+ "HZvYmiNS/z3Od9/jqicR35HkqmtmNovBRDR1NHS/4iWz/8NXekjOgEBNbuPsKuG2"
		+ "jpPrrwoVVrSw");
	
	private static byte[] privateKey = Base64.decode(
		  "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANFI30iMKZ8id42w"
		+ "QsFCQom7uWPikEpjDpr5puegyuQDrOCcWMauEFguZfbgeAqa8LpVeNtQrYmMkpR3"
		+ "nbJpRe/k5/DxqNe2fX6EpzvOKODly2vmkYURw0nwoG7T22vGyOaypETdXASAc6Uc"
		+ "V2X9ui34EDGTAkzghs2MIPFItwtzAgMBAAECgYAvBpbVcFkx3sbKWZ7GWiMlW78u"
		+ "iIwvis6PWCV+yoyMa57+4WK5UgduKQ7USF/w0hvhYq9DaH919tZA8hfHLQx/kMs+"
		+ "ZACsCz36uYGnvZLWYKiZvqw2NSSDAxBCI7uxHsSYmxMRp0R2B6In7gkvMk+tGxU1"
		+ "DM4eT5MbI237XbO6sQJBAPch2YE49X9LZvWUWrmp19hXlv8qtv62l+WMgJF3wGVv"
		+ "NuQvqNw7yIe7Ey3tyD9AxO+RoYXAlg4f9AmElSqunT0CQQDYy1sTsO9BWP+cxBJ/"
		+ "2eLZzejfpiNEr7jUm8AEeDzPA9HQ005Ta7qP0kWBxs8W1yf33qAmPCG9ezYopTZC"
		+ "jjZvAkBH8NymV3Rv1/1i5Ar9HUouOmFEaqTWxUS2mA4dSqUBYjyydIVNh0G68WSF"
		+ "7EBs2Wf67YP9sbB88CRUWPorcKVpAkEAi6fkkfjHB8e3UluUtzu7QSe+PmSeD59L"
		+ "Z9q1hauXMJx7SxT0PhUF56RDFmjl+wa7Ppfxfu/5pEB9EQ3suE84jQJBAOrTDAt+"
		+ "wwk74dM0B/yBdpfuLBlT4PsNAzZ4/K/QpO52FSdTM8ColLkWiRFXLBgi3RMx5Xmx"
		+ "uZVb8Nby74GlYh0=");
	        
	private static byte[] signedDataWithCert = Base64.decode(
		  "MIIFXQYJKoZIhvcNAQcCoIIFTjCCBUoCAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3"
		+ "DQEHAaCCA9QwggPQMIICuKADAgECAgELMA0GCSqGSIb3DQEBBQUAMIGkMQswCQYD"
		+ "VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTERMA8GA1UEBwwIV29vZHNpZGUx"
		+ "FDASBgNVBAoMC1NvbGlkcmEgTExDMR8wHQYDVQQLDBZJbmZvcm1hdGlvbiBUZWNo"
		+ "bm9sb2d5MRQwEgYDVQQDDAsxOTIuMTY4LjEuNzEgMB4GCSqGSIb3DQEJARYRYWRt"
		+ "aW5Ac29saWRyYS5jb20wHhcNMTMwNzIyMDMxMTA0WhcNMTQwNzIyMDMxMTA0WjCB"
		+ "kTEUMBIGA1UEAwwLMTkyLjE2OC4xLjcxEzARBgNVBAgMCkNhbGlmb3JuaWExCzAJ"
		+ "BgNVBAYTAlVTMSAwHgYJKoZIhvcNAQkBFhFhZG1pbkBzb2xpZHJhLmNvbTEUMBIG"
		+ "A1UECgwLU29saWRyYSBMTEMxHzAdBgNVBAsMFkluZm9ybWF0aW9uIFRlY2hub2xv"
		+ "Z3kwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANFI30iMKZ8id42wQsFCQom7"
		+ "uWPikEpjDpr5puegyuQDrOCcWMauEFguZfbgeAqa8LpVeNtQrYmMkpR3nbJpRe/k"
		+ "5/DxqNe2fX6EpzvOKODly2vmkYURw0nwoG7T22vGyOaypETdXASAc6UcV2X9ui34"
		+ "EDGTAkzghs2MIPFItwtzAgMBAAGjgaEwgZ4wCQYDVR0TBAIwADAdBgNVHQ4EFgQU"
		+ "r2Yd1bRR8HqHUIEhis9bARqSBmkwHwYDVR0jBBgwFoAUopaVB7JpnFj8h8vYbi1K"
		+ "DwEtvicwCwYDVR0PBAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMC8GA1UdHwQo"
		+ "MCYwJKAioCCGHmh0dHA6Ly8xOTIuMTY4LjEuNy9tZG10ZXN0LmNybDANBgkqhkiG"
		+ "9w0BAQUFAAOCAQEArpgpd7/Qg+VjU9QZWleK6jSRGqaRe05NyY0wJeVQRicJMEsm"
		+ "mJoETpPmZ4ZXzcs1zcjoOfHQnAm0ctpnQ4JnC6M8uFqQrgiC7jnePAZlfXc+SBjK"
		+ "pyXvT5sQHTs9mJXSbQjBtKkTTRvyGKApifJyMkpOePtJn6GP0YEb7v3H+aTxM4kD"
		+ "clzBSr+iwFs33eHkvOMJeTp+BrpBgcccM300KqLsiEszFPMM+DDnwHSsaI1wshHs"
		+ "aQj/aucFnpxqETkGWRK/ql5QzOZ5qIHtEThZuJwWeWkAkcKJi9he6fMNOGm4fQ1V"
		+ "zFacNIP5N4jP1jIfliwrUPMGexiVBTZe+7QTTzGCAVEwggFNAgEBMIGqMIGkMQsw"
		+ "CQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTERMA8GA1UEBwwIV29vZHNp"
		+ "ZGUxFDASBgNVBAoMC1NvbGlkcmEgTExDMR8wHQYDVQQLDBZJbmZvcm1hdGlvbiBU"
		+ "ZWNobm9sb2d5MRQwEgYDVQQDDAsxOTIuMTY4LjEuNzEgMB4GCSqGSIb3DQEJARYR"
		+ "YWRtaW5Ac29saWRyYS5jb20CAQswCQYFKw4DAhoFADANBgkqhkiG9w0BAQEFAASB"
		+ "gA+XPhn1YMR7YZsEy5eaeAs0nsKfg8ZO9NPa7vfbDZkgWK1GhcQq+rNxZdFm+AYW"
		+ "TgDyqBl/ShccpLJtXRnZreuW1El6fQUdHZvYmiNS/z3Od9/jqicR35HkqmtmNovB"
		+ "RDR1NHS/4iWz/8NXekjOgEBNbuPsKuG2jpPrrwoVVrSw");
	
    static {
    	// Initialze store
    	/*
        X509StreamParser parser;
		try {
			parser = X509StreamParser.getInstance("Certificate", "BC");
	        parser.init(cert);
	        rootCert = (X509Certificate)parser.read();
	        // This is a self signed root so only need one entry
	        JcaCertStoreBuilder bldr = new JcaCertStoreBuilder();
	        bldr.addCertificate(new X509CertificateHolder(cert));
	        store = bldr.build();
	        List certList = new ArrayList();
	        certList.add(rootCert);
	        X509CollectionStoreParameters ccsp = new X509CollectionStoreParameters(certList);
	        store = X509Store.getInstance("Certificate/Collection", ccsp, "BC");
		} catch (Exception e) {
			store = null;
		}
		*/
    }
    
    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

	@After
	public void tearDown() {
		Security.removeProvider(BC);
	}
	
	@Test
	public void testGetAndVerifySignedContent() throws Exception {
		
		RSAKeyPair	caKeys = new RSAKeyPair();
		RSAKeyPair	intKeys = new RSAKeyPair();
		RSAKeyPair	myKeys = new RSAKeyPair();

        X509Certificate[] chain = new X509Certificate[3];
    	
		caKeys.generate(
				new RSAPrivateCrtKeySpec(
					new BigInteger("a5226e241a19f5b796ef2326f4f580b1e5cbc05360a7fd94fd8d59013115e077a422beb4904c5e57f0d9827a0da98b337ab8d47a2b24f77d83f9689e9b43af6b23bf39a1e4e87d8ce9f7d68b8dd50ffec1d34b25833848325ed035d3a1ddeaf62fe5a184dec918d7c2e8b89b17b057a9af359280956dc2a393be6e9a04517b25", 16),
					new BigInteger("10001", 16),
					new BigInteger("6ff223507e11532e1e380750858758b340e11b846a65f7d664fcc975b15cef4aac0e91d1be70c7143ec6755960a1ab283eedc5bcfc3a973c9397248141286565d479dd57d9bc01d4dec645dd1ae01590671315ec6f9bcde606707255382fcb363744a8bcda3c7a3c2e4015d450ed4aafb675ae277ddcf0e779165125a84f6681", 16),
					new BigInteger("f8e745cf5388418a0f038b425095aa8ce3cae42764c15d6f91021a0b6fe0746653428ac95c88ce127deae745521805b6a53da780b56c3f4d15f0c88a85a19609", 16),
					new BigInteger("a9d7bc0903893d8116ad8df22e425df382f895d47c0a47d7ea182e9a6221f3d1b27cdfd278960d8cc65699a5c1e5e17197805c9954ff6c37c19a0d9e2241a33d", 16),
					new BigInteger("88181ca9a228ec7d0a7c8b9674ed80d58c701194209941f790b82f797570aaf4902de028fdb9a7c3a0a9e24e9af69b99247cb3abc2872f8d7ca3ad636071dbd1", 16),
					new BigInteger("5f024cb0aa26ba9e1cc68772238882aff6e30245b401b840c33635d3acf39b4601d7b30934e593bcdd32928ed411b97466b0aa9c279d1eb76df8b48772584f6d", 16),
					new BigInteger("e9774efb165c4309e7c7f32603d882d2e8b728887ddb50ee2c2e89591d192b64058699d3251e01348ee24dd23669aec43f1b4e16266950f6268e632242b7d500", 16)),
				new RSAPublicKeySpec(
					new BigInteger("a5226e241a19f5b796ef2326f4f580b1e5cbc05360a7fd94fd8d59013115e077a422beb4904c5e57f0d9827a0da98b337ab8d47a2b24f77d83f9689e9b43af6b23bf39a1e4e87d8ce9f7d68b8dd50ffec1d34b25833848325ed035d3a1ddeaf62fe5a184dec918d7c2e8b89b17b057a9af359280956dc2a393be6e9a04517b25", 16),
					new BigInteger("10001", 16)));
        chain[2] = X509CertificateGenerator.createV3RootCA(
        		caKeys.getPublicKey(),
        		caKeys.getPrivateKey(),
        		1, 365,
        		"CN=Root Test, L=US,O=Acme Inc,OU=Root Certificate", 
        		null,	// set issuer=subject
        		"Root Certificate");
        
        intKeys.generate(
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
        chain[1] = X509CertificateGenerator.createIntermediateCA(
        		intKeys.getPublicKey(),
        		(X509Certificate) chain[2],
        		caKeys.getPrivateKey(),
        		2, 365,
        		"CN=Intermediate Test, L=US,O=Acme Inc.,OU=Intermediate Certificate",
        		null,
        		"Intermediate Certificate");

        myKeys.generate(
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
        chain[0] = X509CertificateGenerator.createCert(
        		myKeys.getPublicKey(),
        		(X509Certificate) chain[1],
        		intKeys.getPrivateKey(),
        		1, 365,
        		"L=US,O=Acme Inc.,OU=EndEntity Certificate,CN=Paul Glendenning",
        		"http://www/acme.com/crl1.lst;http://www/acme.com/crl2.lst",
        		"Leaf Certificate");
        
        
        Store certs = new JcaCertStore(Arrays.asList(chain));
        // set up the generator
        CMSSignedDataGenerator gen = PKCS7Signer.createGenerator(chain[0], myKeys.getPrivateKey(), "SHA1withRSA", certs);

        String originalContent = "Hello World";
        // create the signed-data object using UTF-8 encoding
        byte[] signedContent = PKCS7Signer.sign(originalContent.getBytes(Charset.forName("UTF-8")), gen);
        String decodedContent = new String(PKCS7Signer.getAndVerifyContent(signedContent, chain[2]), Charset.forName("UTF-8"));
        assertTrue(decodedContent != null);
        assertTrue(decodedContent.equals(originalContent));
	}

}
