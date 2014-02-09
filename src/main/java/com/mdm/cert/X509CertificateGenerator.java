package com.mdm.cert;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.StringTokenizer;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

/**
 * @author paul
 *
 */
@SuppressWarnings("deprecation")
public class X509CertificateGenerator {
	
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	
	private X509CertificateGenerator() {
	}
	
	/*
	 * Help to get a calendar moved back in time to last minute
	 */
	private static Calendar getCalendar() {
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.MILLISECOND, 0);
        calendar.set(Calendar.SECOND, 0);
        calendar.add(Calendar.MINUTE, -1);
        return calendar;
	}
	
	/*
	 * Helper to parse a colon separated list of CRL distribution points.
	 */
	private static DistributionPoint[] getCRLDisributionPoints(String crlDistributionPoints) {
		
		if (crlDistributionPoints != null) {
			// List of CRLs
			StringTokenizer tokenizer = new StringTokenizer(crlDistributionPoints, ";", false);
			ArrayList<DistributionPoint> distpoints = new ArrayList<DistributionPoint>();
			while (tokenizer.hasMoreTokens()) {
				// 6 is URI
				String uri = tokenizer.nextToken();
				GeneralName gn = new GeneralName(6, new DERIA5String(uri));
			
				ASN1EncodableVector vec = new ASN1EncodableVector();
				vec.add(gn);
			
				org.bouncycastle.asn1.x509.GeneralNames gns = 
					org.bouncycastle.asn1.x509.GeneralNames.getInstance(new DERSequence(vec));
				DistributionPointName dpn = new DistributionPointName(0, gns);
				distpoints.add(new DistributionPoint(dpn, null, null));
			}
		}
		return null;
	}

	/*
	 * Helper to parse a colon separated list of CRL distribution points.
	 */
	private static void addCRLDisributionPointExtension(X509v3CertificateBuilder certBuilder, String crlDistributionPoints) throws CertIOException {
		
		DistributionPoint[] dp = getCRLDisributionPoints(crlDistributionPoints);
		if (dp != null) {
			certBuilder.addExtension(X509Extension.cRLDistributionPoints, false, new CRLDistPoint(dp));
		}
	}
	
	/**
	 * Helper to build issuer or subject string.
	 */
	public static String buildX500PrincipleString(String country, String state, String location, 
									String organization, String organizationUnit,
									String commonName, String email) {
		
		StringBuilder bldr = new StringBuilder();

		if (country != null) {
			bldr.append("C=");
			bldr.append(country);
		}
		if (state != null) {
			bldr.append("ST=");
			bldr.append(state);
		}
        if (location != null) {
			bldr.append("L=");
			bldr.append(location);
        }
		if (organization != null) {
			bldr.append("O=");
			bldr.append(organization);
		}
		if (organizationUnit != null) {
			bldr.append("OU=");
			bldr.append(organizationUnit);
		}
        if (commonName != null) {
			bldr.append("CN=");
			bldr.append(commonName);
        }
        if (email != null) {
			bldr.append("EmailAddress=");
			bldr.append(email);
		}
        return bldr.toString();
	}
	
    /**
     * Get a unique key which identifies the certificate.
     * @param	cert	The certificate.
     * @return	An IssuerAndSerialNumber.
     */
	public static IssuerAndSerialNumber getIssuerAndSerialNumber(X509Certificate cert) {
		X509CertificateHolder holder = null;
		try {
			holder = new X509CertificateHolder(cert.getEncoded());
	    	return new IssuerAndSerialNumber(holder.getIssuer(), holder.getSerialNumber());
		} catch (Exception e) {
		}
		return null;
	}
    
	/**
     * Create a v1 self signed root certificate.
     */
    public static X509Certificate createV1RootCA(PublicKey pubKey, PrivateKey  privKey, 
			long serialNumber, int durationInDays,
			String subject, String issuer, String friendlyName) throws Exception {
    	
    	if (issuer == null)
    		issuer = subject;

        // Mandatory
        Calendar calendar = getCalendar();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.DATE, durationInDays);
        Date notAfter = calendar.getTime();
        JcaX509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder(
        		new X500Principal(issuer), 
        		BigInteger.valueOf(serialNumber), 
        		notBefore, notAfter, 
        		new X500Principal(subject), // doesn't need to be the same as issuer
        		pubKey);

        // Signing
        ContentSigner certSigner = new JcaContentSignerBuilder("SHA1WithRSAEncryption")
        			.setProvider(BC).build(privKey);

        X509CertificateHolder certHolder = certBuilder.build(certSigner);

        // Extract a JCA-compatible certificate
        X509Certificate cert = new JcaX509CertificateConverter()
        			.setProvider(BC).getCertificate(certHolder);
        
        cert.checkValidity(new Date());
        cert.verify(pubKey);

        // Optionally set the friendly name. If this is not set the CN will
        // be used as the certificate name in the key store.
        if (friendlyName != null) {
            // Can only do this if BC is the provider
            PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)cert;

	        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
	            new DERBMPString(friendlyName));
        }
        return cert;
    }

    /**
     * Create a v3 self signed root certificate.
     */
	public static X509Certificate createV3RootCA(PublicKey pubKey, PrivateKey  privKey, 
				long serialNumber, int durationInDays,
				String subject, String issuer, String friendlyName) throws Exception {
    	
    	if (issuer == null)
    		issuer = subject;

        // Mandatory
        Calendar calendar = getCalendar();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.DATE, durationInDays);
        Date notAfter = calendar.getTime();
        BigInteger issuerSerialNumber = BigInteger.valueOf(serialNumber);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
        		new X500Principal(issuer),
        		issuerSerialNumber,
        		notBefore, notAfter,
        		new X500Principal(subject),
        		pubKey);
        
        // Optional extensions
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(true));
        certBuilder.addExtension(X509Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign|KeyUsage.cRLSign|KeyUsage.digitalSignature));
        certBuilder.addExtension(X509Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pubKey));
        /* FIXME: avoid hack
        new AuthorityKeyIdentifier(
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubKey),
                new GeneralNames(new GeneralName(new X500Name(issuer))),
                issuerSerialNumber);
        */
        // Signing
        ContentSigner certSigner = new JcaContentSignerBuilder("SHA1WithRSAEncryption")
        							.setProvider(BC)
        							.build(privKey);
        X509CertificateHolder certHolder = certBuilder.build(certSigner);

 
        // Hack - add authority key now
        certBuilder.addExtension(X509Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(certHolder));
        certSigner = new JcaContentSignerBuilder("SHA1WithRSAEncryption")
							.setProvider(BC).build(privKey);
        certHolder = certBuilder.build(certSigner);
        
        // Extract a JCA-compatible certificate
        X509Certificate cert = new JcaX509CertificateConverter()
        				.setProvider(BC).getCertificate(certHolder);
        
        cert.checkValidity(new Date());
        cert.verify(pubKey);

        // Optionally set the friendly name. If this is not set the CN will
        // be used as the certificate name in the key store.
        if (friendlyName != null) {
            // Can only do this if BC is the provider
            PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)cert;

	        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
	            new DERBMPString(friendlyName));
        }
        return cert;
    }
	
    /**
     * Generate a intermediate CA signed by another CA
     */
	public static X509Certificate createIntermediateCA(AsymmetricKeyParameter pubKey, X509Certificate caCert, AsymmetricKeyParameter caPrivKey,
				long serialNumber, int durationInDays,
				String subject, String crlDistributionPoints, String friendlyName) throws Exception {
    	
        // Mandatory
		X509CertificateHolder holder = new X509CertificateHolder(caCert.getEncoded());
		SubjectPublicKeyInfo subjectKeyId = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubKey);
        BigInteger serial = BigInteger.valueOf(serialNumber);
        Calendar calendar = getCalendar();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.DATE, durationInDays);
        Date notAfter = calendar.getTime();
        X500Name requesterSubject = new X500Name(subject);
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(holder.getSubject(), serial, notBefore, notAfter, requesterSubject, subjectKeyId);

        // Optional extensions
        BcX509ExtensionUtils extUtils = new BcX509ExtensionUtils();
        certBuilder.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(0));
        certBuilder.addExtension(X509Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign|KeyUsage.cRLSign|KeyUsage.digitalSignature));
        certBuilder.addExtension(X509Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectKeyId));
        certBuilder.addExtension(X509Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(holder));
        addCRLDisributionPointExtension(certBuilder, crlDistributionPoints);

        // Signing
        AlgorithmIdentifier sigAlg = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        AlgorithmIdentifier digAlg = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlg);
        ContentSigner certSigner = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(caPrivKey);        
        X509CertificateHolder certHolder = certBuilder.build(certSigner);

        // Extract a JCA-compatible certificate
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider(BC);
        X509Certificate cert = converter.getCertificate(certHolder);
        
        cert.checkValidity(new Date());
        cert.verify(caCert.getPublicKey());

        // Optionally set the friendly name.
        if (friendlyName != null) {
            // Can only do this if BC is the provider
            PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)cert;

	        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
	            new DERBMPString(friendlyName));
        }

        return cert;
    }
    
    /**
     * Generate a intermediate CA signed by another CA
     */
	public static X509Certificate createIntermediateCA(PublicKey pubKey, X509Certificate caCert, PrivateKey caPrivKey,
				long serialNumber, int durationInDays,
				String subject, String crlDistributionPoints, String friendlyName) throws Exception {
    	
        // Mandatory
		// Must deep copy the issuer DN
        Calendar calendar = getCalendar();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.DATE, durationInDays);
        Date notAfter = calendar.getTime();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
        		caCert.getSubjectX500Principal(),
        		BigInteger.valueOf(serialNumber),
        		notBefore, notAfter,
        		new X500Principal(subject),
        		pubKey);

        // Optional extensions
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(0));
        certBuilder.addExtension(X509Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign|KeyUsage.cRLSign|KeyUsage.digitalSignature));
        certBuilder.addExtension(X509Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pubKey));
        certBuilder.addExtension(X509Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert));
        addCRLDisributionPointExtension(certBuilder, crlDistributionPoints);

        // Signing
        ContentSigner certSigner = new JcaContentSignerBuilder("SHA1WithRSAEncryption")
        			.setProvider(BC).build(caPrivKey);
        X509CertificateHolder certHolder = certBuilder.build(certSigner);

        // Extract a JCA-compatible certificate
        X509Certificate cert = new JcaX509CertificateConverter()
        			.setProvider(BC).getCertificate(certHolder);
        
        cert.checkValidity(new Date());
        cert.verify(caCert.getPublicKey());

        // Optionally set the friendly name.
        if (friendlyName != null) {
            // Can only do this if BC is the provider
            PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)cert;

	        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
	            new DERBMPString(friendlyName));
        }

        return cert;
    }
    
    /**
     * Generate a leaf certificate signed by a CA
     */
	public static X509Certificate createCert(PublicKey pubKey, X509Certificate caCert, PrivateKey caPrivKey,
				long serialNumber, Date notAfter,
				String subject, String crlDistributionPoints, String friendlyName) throws Exception {
    	
        // Mandatory
        Calendar calendar = getCalendar();
        Date notBefore = calendar.getTime();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
        		caCert.getSubjectX500Principal(),
        		BigInteger.valueOf(serialNumber),
        		notBefore, notAfter,
        		new X500Principal(subject),
        		pubKey);

        // Optional extensions
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(X509Extension.basicConstraints, false, new BasicConstraints(false));
        certBuilder.addExtension(X509Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature|KeyUsage.keyEncipherment));
        certBuilder.addExtension(X509Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pubKey));
        certBuilder.addExtension(X509Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert));
        addCRLDisributionPointExtension(certBuilder, crlDistributionPoints);

        // Signing
        // PrivateKey requesterPrivKey = requesterKeyPair.getPrivate(); // from generated key pair
        ContentSigner certSigner = new JcaContentSignerBuilder("SHA1WithRSAEncryption")
        			.setProvider(BC).build(caPrivKey);

        X509CertificateHolder certHolder = certBuilder.build(certSigner);

        // Extract a JCA-compatible certificate
        X509Certificate cert = new JcaX509CertificateConverter()
        			.setProvider(BC).getCertificate(certHolder);
        
        cert.checkValidity(new Date());
        cert.verify(caCert.getPublicKey());

        // Optionally set the friendly name.
        if (friendlyName != null) {
            // Can only do this if BC is the provider
            PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)cert;

	        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
	            new DERBMPString(friendlyName));
        }
        
        return cert;
    }
	
    /**
     * Generate a leaf certificate signed by a CA
     */
	public static X509Certificate createCert(PublicKey pubKey, X509Certificate caCert, PrivateKey caPrivKey,
				long serialNumber, int durationInDays,
				String subject, String crlDistributionPoints, String friendlyName) throws Exception {
    	
        // Mandatory
        Calendar calendar = getCalendar();
        calendar.add(Calendar.DATE, durationInDays);
        return createCert(pubKey, caCert, caPrivKey, serialNumber, calendar.getTime(), subject, crlDistributionPoints, friendlyName);
    }
	
	/**
	 * Save a PKCS12 container
	 */
	public static void savePKCS12(OutputStream os, String friendlyName, String passwd, PrivateKey privKey, Certificate[] chain) 
			throws NoSuchAlgorithmException, CertificateException, IOException,
					KeyStoreException, NoSuchProviderException, InvalidKeyException {
		
		X509Certificate cert = (X509Certificate)chain[0];
		PublicKey pubKey = cert.getPublicKey();

        // Can only do this if BC is the provider
		//
        // For the browser to recognize the association between a private key 
		// its certificate the pkcs_9_localKeyId OID should be set the same
		// for both.
        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)privKey;

        bagAttr.setBagAttribute(
            PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
            new SubjectKeyIdentifierStructure(pubKey));
        
        bagAttr = (PKCS12BagAttributeCarrier)cert;
        bagAttr.setBagAttribute(
                PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                new SubjectKeyIdentifierStructure(pubKey));
        
        // store the key and the certificate chain
        KeyStore store = KeyStore.getInstance("PKCS12", BC);

        store.load(null, null);

        // if you haven't set the friendly name and local key id above
        // the name below will be the name of the key
        store.setKeyEntry(friendlyName, privKey, null, chain);

        store.store(os, passwd.toCharArray());
	}
    
}
