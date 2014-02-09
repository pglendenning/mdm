package com.mdm.cert;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

@SuppressWarnings("deprecation")
public final class X509CrlGenerator {
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	
	public static X509CRL _generateInitialCRL(X509Certificate caCert, PrivateKey caPrivKey) 
		throws GeneralSecurityException {
		try {
		    X509V2CRLGenerator crlGen = new X509V2CRLGenerator();
		    crlGen.setIssuerDN(caCert.getIssuerX500Principal());
		    
		    Date validFrom = caCert.getNotBefore();
	        Date validTo = caCert.getNotAfter();
		    crlGen.setThisUpdate(validFrom);
		    crlGen.setNextUpdate(validTo);
		    
		    crlGen.setSignatureAlgorithm("SHA1withRSAEncryption");
		    crlGen.addExtension(X509Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
		    crlGen.addExtension(X509Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
		    return crlGen.generate(caPrivKey, BC);

		} catch (Exception ex) {
		    ex.printStackTrace();
		}
		throw new GeneralSecurityException();
	}
	
	public static X509CRL _generateUpdate(X509Certificate caCert, PrivateKey caPrivKey, List<X509Certificate> revoked)
			throws GeneralSecurityException {
		// TODO: should add to current CRL
		try {
		    X509V2CRLGenerator crlGen = new X509V2CRLGenerator();
		    crlGen.setIssuerDN(caCert.getIssuerX500Principal());
		    
	        Calendar calendar = Calendar.getInstance();
		    Date now = calendar.getTime();
		    crlGen.setThisUpdate(now);
	        calendar.add(Calendar.YEAR, 1);
	        Date nextYear = calendar.getTime();
		    crlGen.setNextUpdate(nextYear);
		    
		    crlGen.setSignatureAlgorithm("SHA1withRSAEncryption");
		    
		    // TODO process list
		    Iterator<X509Certificate> iterator = revoked.iterator();
			while (iterator.hasNext()) {
			    crlGen.addCRLEntry(iterator.next().getSerialNumber(), nextYear, CRLReason.superseded);
			}
		    
		    crlGen.addExtension(X509Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
		    crlGen.addExtension(X509Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
		    return crlGen.generate(caPrivKey, BC);
		}
		catch (Exception ex) {
		    ex.printStackTrace();
		}
		throw new GeneralSecurityException();
	}

	public static X509CRL generateEmptyCRL(X509Certificate caCert, PrivateKey caPrivKey, Date thisUpdate, Date nextUpdate) 
			throws GeneralSecurityException {
		
		if (thisUpdate.after(nextUpdate) || thisUpdate.equals(nextUpdate))
			throw new GeneralSecurityException();
	
		try {
			JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(caCert, thisUpdate);
			builder.setNextUpdate(nextUpdate);
			
	        // Signing
	        ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSAEncryption")
	        			.setProvider(BC).build(caPrivKey);
	        
	        X509CRLHolder crlHolder = builder.build(signer);

	        // Extract a JCA-compatible CRL
	        return new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

		} catch (Exception ex) {
		    ex.printStackTrace();
		}
		throw new GeneralSecurityException();
	}

	public static X509CRL generateCaCompromiseCRL(X509Certificate caCert, PrivateKey caPrivKey, Date thisUpdate, Date nextUpdate) 
			throws GeneralSecurityException {
		
		if (thisUpdate.after(nextUpdate) || thisUpdate.equals(nextUpdate))
			throw new GeneralSecurityException();
	
		try {
			JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(caCert, thisUpdate);
			builder.setNextUpdate(nextUpdate);
			builder.addCRLEntry(caCert.getSerialNumber(), thisUpdate, CRLReason.cACompromise);
			
	        // Signing
	        ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSAEncryption")
	        			.setProvider(BC).build(caPrivKey);
	        
	        X509CRLHolder crlHolder = builder.build(signer);

	        // Extract a JCA-compatible CRL
	        return new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

		} catch (Exception ex) {
		    ex.printStackTrace();
		}
		throw new GeneralSecurityException();
	}

	public static X509CRL revokeCertificate(X509Certificate caCert, PrivateKey caPrivKey, BigInteger userCertificateSerial, Date thisUpdate, Date nextUpdate) 
			throws GeneralSecurityException {
		
		if (thisUpdate.after(nextUpdate) || thisUpdate.equals(nextUpdate))
			throw new GeneralSecurityException();
	
		try {
			JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(caCert, thisUpdate);
			builder.setNextUpdate(nextUpdate);
			builder.addCRLEntry(caCert.getSerialNumber(), thisUpdate, CRLReason.cACompromise);
			builder.addCRLEntry(userCertificateSerial, thisUpdate, CRLReason.cACompromise);
			
	        // Signing
	        ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSAEncryption")
	        			.setProvider(BC).build(caPrivKey);
	        
	        X509CRLHolder crlHolder = builder.build(signer);

	        // Extract a JCA-compatible CRL
	        return new JcaX509CRLConverter().setProvider(BC).getCRL(crlHolder);

		} catch (Exception ex) {
		    ex.printStackTrace();
		}
		throw new GeneralSecurityException();
	}


}
