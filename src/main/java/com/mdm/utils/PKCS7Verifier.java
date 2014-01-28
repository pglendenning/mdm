package com.mdm.utils;

import java.security.GeneralSecurityException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * Class for verifying the content of a signed and encapsulated PCKS7 message.
 */
public class PKCS7Verifier {
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

	private PKCS7Verifier() {
	}
	
    /**
     * Helper for verifying signed content.
     * Note: the path is built with revocation checking turned off.
     * @throws CertificateVerificationException 
     */
    private static PKIXCertPathBuilderResult buildPath(X509Certificate rootCert, X509CertSelector endConstraints,
    		CertStore certsAndCRLs) throws CertificateVerificationException {
    	try {
	    	CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", BC);
	    	PKIXBuilderParameters params = new PKIXBuilderParameters(
	    			Collections.singleton(new TrustAnchor(rootCert, null)), endConstraints);
	    	params.addCertStore(certsAndCRLs);
	    	params.setRevocationEnabled(false);
	    	return (PKIXCertPathBuilderResult) builder.build(params);
	    	
    	} catch (Exception e) {
    		throw new CertificateVerificationException("cannot generate PKIXCertPathBuilderResult");
    	}
    }
    
    /**
     * Helper for verifying signed content.
     * Note: the path is built with revocation checking turned off.
     * @throws CertificateVerificationException 
     */
    private static PKIXCertPathBuilderResult buildPath(X509CertSelector endConstraints,
    		CertStore certsAndCRLs) throws CertificateVerificationException {
    	
    	try {
	    	Collection<?> certs = certsAndCRLs.getCertificates(null);
	        Iterator<?> it = certs.iterator();
	        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
	        while (it.hasNext()) {
	        	X509Certificate rootCert = (X509Certificate)it.next();
	        	if (X509CertificateVerifier.isSelfSigned(rootCert)) {
	        		// TODO: check this root certificate is trusted
	    	    	trustAnchors.add(new TrustAnchor(rootCert, null));
	        	}
	        }
	 
	    	CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", BC);
	    	PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, endConstraints);
	    	params.addCertStore(certsAndCRLs);
	    	params.setRevocationEnabled(false);
	    	return (PKIXCertPathBuilderResult) builder.build(params);
	    	
    	} catch (Exception e) {
    		throw new CertificateVerificationException("cannot generate PKIXCertPathBuilderResult");
    	}
    }
    
    /*
     * Helper for verifying signed content.
     */
    private static boolean[] getKeyUsage(int mask)
    {
        byte[] bytes = new byte[] { (byte)(mask & 0xff), (byte)((mask & 0xff00) >> 8) };
        boolean[] keyUsage = new boolean[9];

        for (int i = 0; i != 9; i++)
        {
            keyUsage[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
        }

        return keyUsage;
    }
    
    /**
     * Take a CMS SignedData message and a trust anchor and determine if the
     * message is signed with a valid signature from an end entity entity
     * certificate recognized by the trust anchor rootCert.
     * 
     * @param  signedData
     * 				CMS signed and encapsulated data.
     * @param  rootCert
     * 				A trust anchor root certificate.
     * @return True if verification is successful.
     */
    public static boolean isValid(CMSSignedData signedData, X509Certificate rootCert) {
    	
    	CertificateVerificationResult result;
		try {
			result = verify(signedData, rootCert);
			return result.isValid();
		} catch (CertificateVerificationException e) {
		}
    	return false;
    }
 
    /**
     * Take a CMS SignedData message and a trust anchor and determine if the
     * message is signed with a valid signature from an end entity entity
     * certificate recognized by the trust anchor rootCert.
     * 
     * @param  signedData
     * 				CMS signed and encapsulated data.
     * @param  rootCert
     * 				A trust anchor root certificate.
     * @return The verification result.
     * @throws CertificateVerificationException
     */
    public static CertificateVerificationResult verify(CMSSignedData signedData, X509Certificate rootCert) 
    		throws CertificateVerificationException {
    	
        try {
			CertStore certsAndCRLs = new JcaCertStoreBuilder().setProvider(BC)
							.addCertificates(signedData.getCertificates()).build();
			SignerInformationStore signers = signedData.getSignerInfos();
			Iterator<?> it = signers.getSigners().iterator();
			if (it.hasNext())
			{
			    SignerInformation signer = (SignerInformation)it.next();
			    X509CertSelector signerConstraints = new JcaX509CertSelectorConverter().getCertSelector(signer.getSID());
			    signerConstraints.setKeyUsage(getKeyUsage(KeyUsage.digitalSignature));
			    PKIXCertPathBuilderResult result = buildPath(rootCert, signerConstraints, certsAndCRLs);
			    boolean verified = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC)
			    			.build((X509Certificate)result.getCertPath().getCertificates().get(0)));
			    return new CertificateVerificationResult(result, verified);
			}
			throw new CertificateVerificationException("No signers");
		} catch (GeneralSecurityException e1) {
    		throw new CertificateVerificationException(e1.getMessage());
		} catch (CMSException e2) {
    		throw new CertificateVerificationException(e2.getMessage());			
		} catch (OperatorCreationException e3) {
    		throw new CertificateVerificationException(e3.getMessage());			
		}
    }
 
    /**
     * Take a CMS SignedData message and a trust anchor and determine if the
     * message is signed with a valid signature from an end entity entity
     * certificate recognized by a trust anchor in the .
     * 
     * @param  signedData
     * 				CMS signed and encapsulated data.
     * @param  rootCert
     * 				A trust anchor root certificate.
     * @return The verification result.
     * @throws CertificateVerificationException
     */
    public static CertificateVerificationResult verify(CMSSignedData signedData) throws CertificateVerificationException {
    	
        try {
			CertStore certsAndCRLs = new JcaCertStoreBuilder().setProvider(BC)
					.addCertificates(signedData.getCertificates()).build();
			SignerInformationStore signers = signedData.getSignerInfos();
			Iterator<?> it = signers.getSigners().iterator();
			if (it.hasNext())
			{
			    SignerInformation signer = (SignerInformation)it.next();
			    X509CertSelector signerConstraints = new JcaX509CertSelectorConverter().getCertSelector(signer.getSID());
			    signerConstraints.setKeyUsage(getKeyUsage(KeyUsage.digitalSignature));
			    PKIXCertPathBuilderResult result = buildPath(signerConstraints, certsAndCRLs);
			    boolean verified = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC)
			    			.build((X509Certificate)result.getCertPath().getCertificates().get(0)));
			    return new CertificateVerificationResult(result, verified);
			}
			throw new CertificateVerificationException("No signers");
		} catch (GeneralSecurityException e1) {
    		throw new CertificateVerificationException(e1.getMessage());
		} catch (CMSException e2) {
    		throw new CertificateVerificationException(e2.getMessage());			
		} catch (OperatorCreationException e3) {
    		throw new CertificateVerificationException(e3.getMessage());			
		}
    }
}
