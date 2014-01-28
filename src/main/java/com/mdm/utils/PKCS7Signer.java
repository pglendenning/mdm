/**
 * 
 */
package com.mdm.utils;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

import edu.emory.mathcs.backport.java.util.Arrays;

/**
 * Class for creating a signed and encapsulated PCKS7 message.
 */
public class PKCS7Signer {
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	
	private PKCS7Signer() {
	}

	public static KeyStore loadKeyStore(InputStream is, String password) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException  {
	
	    KeyStore keystore = KeyStore.getInstance(BC);
	    keystore.load(is, password.toCharArray());
	    return keystore;
	}
	
	/**
     * Create a PCKS7 signed data generates using the certificate chain in the
     * store. The complete chain from end entity to the trusted anchor must
     * be present.
	 * 
	 * @param  cert
	 * 				The end entity certificate.
	 * @param privKey
	 * 				The end entity private key.
	 * @param algorithm
     * 				The algorithm to use for signing and encrypting, for example "SHA1withRSA".
	 * @param certstore
	 * 				The certificate store.
     * @return A CMS data generator.
	 * @throws CertificateEncodingException
	 * @throws OperatorCreationException
	 * @throws CMSException
	 */
    public static CMSSignedDataGenerator createGenerator(X509Certificate cert, PrivateKey privKey, String algorithm, Store certstore)
    		throws CertificateEncodingException, OperatorCreationException, CMSException {
        
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder()
        			.setProvider(BC)
        			.build(algorithm, privKey, (X509Certificate)cert));
        generator.addCertificates(certstore); 
        /* TODO: remove later, now keep for reference
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATUREALGO).setProvider(BC).build(privKey);

        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).
                build()).build(signer, (X509Certificate)cert));
        generator.addCertificates(certstore);
        */
        return generator;
    }

    /**
     * Create a PCKS7 signed data generates using the certificate chain in the
     * key store. The complete chain form end entity to the trusted anchor must
     * be present.
     * 
     * @param  keystore
     * 				The key store.
     * @param  keyAlias
     * 				The name of the end entity key.
     * @param  passwd
     * 				The key store password.
     * @param  algorithm
     * 				The algorithm to use for signing and encrypting, for example "SHA1withRSA".
     * @return A CMS data generator.
     * @throws KeyStoreException
     * @throws CertificateEncodingException
     * @throws UnrecoverableKeyException
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     * @throws CMSException
     */
    public static CMSSignedDataGenerator createGenerator(final KeyStore keystore, String keyAlias, String passwd, String algorithm) 
    		throws KeyStoreException, CertificateEncodingException, UnrecoverableKeyException, 
    		OperatorCreationException, NoSuchAlgorithmException, CMSException  {

        Certificate[] chain = (Certificate[]) keystore.getCertificateChain(keyAlias);
        Certificate cert = keystore.getCertificate(keyAlias);
        PrivateKey privKey = (PrivateKey)keystore.getKey(keyAlias, passwd.toCharArray());
        Store certstore = new JcaCertStore(Arrays.asList(chain));
        
        if (cert == null || !cert.equals(chain[0]))
        {
        	throw new UnrecoverableKeyException("Certificate not attached to private key");
        }
        return createGenerator((X509Certificate)cert, privKey, algorithm, certstore);
    }

    /**
     * Verify the signature and extract the content. The end entity certificate
     * must recognized by the trust anchor rootCert.
     * 
     * @param  signedData
     * 				CMS signed and encapsulated data.
     * @param  rootCert
     * 				A trust anchor root certificate.
     * @return The original content or null if the signature fails verification.
     */
    public static byte[] getAndVerifyContent(CMSSignedData signedData, X509Certificate rootCert) {
    	
		if (PKCS7Verifier.isValid(signedData, rootCert))
		{
			CMSProcessable signedContent = signedData.getSignedContent();
			byte[] originalContent = (byte[]) signedContent.getContent();
			return originalContent;
		}
		return null;    	
    }

    /**
     * Verify the signature and extract the content. The end entity certificate
     * must recognized by the trust anchor rootCert.
     * 
     * @param  signedBytes
     * 				The signed content.
     * @param  rootCert
     * 				A trust anchor root certificate.
     * @return The original content or null if the signature fails verification.
     */
    public static byte[] getAndVerifyContent(final byte[] signedBytes, X509Certificate rootCert) 
    		throws CMSException {
    	
    	CMSSignedData s = new CMSSignedData(signedBytes);
    	return getAndVerifyContent(s, rootCert);
    }

    /**
     * Extract the content. Use PKCS7Verifier to verify the signed content.
     * 
     * @param  signedBytes
     * 				The signed content.
     * @return The original content or null if the signature fails verification.
     * @throws CMSException if signedBytes is not a valid encoding.
     */
    public static byte[] getContent(final byte[] signedBytes) throws CMSException {

		CMSSignedData s = new CMSSignedData(signedBytes);
		CMSProcessable signedContent = s.getSignedContent();
		byte[] originalContent = (byte[]) signedContent.getContent();
		return originalContent;
    }
    
    /**
     * Extract the content. Use PKCS7Verifier to verify the signed content.
     * 
     * @param  signedData
     * 				The signed content.
     * @return The original content or null if the signature fails verification.
     * @throws CMSException if signedBytes is not a valid encoding.
     */
    public static byte[] getContent(CMSSignedData signedData) throws CMSException {

		CMSProcessable signedContent = signedData.getSignedContent();
		byte[] originalContent = (byte[]) signedContent.getContent();
		return originalContent;
    }
    
    /**
     * Create a signed and encapsulated PCKS7 message.
     * @param  content
     * 				The content to sign and encapsulate.
     * @param  generator
     * 				A signed data generator.
     * @return The signed PKCS7 message.
     * @throws CMSException
     * @throws IOException
     * @see	createGenerator().
     */
     public static byte[] sign(final byte[] content, final CMSSignedDataGenerator generator) throws CMSException, IOException {

        CMSTypedData cmsdata = new CMSProcessableByteArray(content);
        CMSSignedData signeddata = generator.generate(cmsdata, true);
        return signeddata.getEncoded();
    }
    
     /**
      * Create a base64 encoded signed and encapsulated PCKS7 message.
      * @param  content
      * 				The content to sign and encapsulate.
      * @param  generator
      * 				A signed data generator.
      * @return The encoded PKCS7 message.
      * @throws CMSException
      * @throws IOException
      * @see	createGenerator().
      */
    public static byte[] signBase64(final byte[] content, final CMSSignedDataGenerator generator) throws CMSException, IOException  {

        CMSTypedData cmsdata = new CMSProcessableByteArray(content);
        CMSSignedData signeddata = generator.generate(cmsdata, true);
        return Base64.encode(signeddata.getEncoded());
    }    
}
