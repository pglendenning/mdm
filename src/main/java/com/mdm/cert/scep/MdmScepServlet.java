package com.mdm.cert.scep;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.server.ScepServlet;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.OperationFailureException;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.response.Capability;
import org.jscep.util.CertificationRequestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mdm.cert.IssuedCertificateIdentifier;
import com.mdm.utils.MdmServiceProperties;

/**
 * Servlet implementation class IosScepServlet
 */
@WebServlet(description = "MDM Scep Server", urlPatterns = { "/scep/pkiclient.exe" })
public class MdmScepServlet extends ScepServlet {
	public final static String CA_CERT = "CA_Cert";
	public final static String CA_PRIVKEY = "CA_PrivKey";
	public final static String CA_CERT_IASN = "CA_IASN";
	public final static String CA_CERT_CRL = "CA_CRL";
	public final static String CA_CERT_NEXT = "CA_CertNext";
	public final static String RA_CERT = "RA_Cert";
	public final static String RA_PRIVKEY = "RA_PrivKey";
	public final static String SESSION_PASSWD = "ChallangePASSWD";
	public final static String BC = "BC";
	
	private static final Logger LOG = LoggerFactory.getLogger(MdmScepServlet.class);
	private static final long serialVersionUID = 1L;
    private static final Map<IssuerAndSerialNumber, X509Certificate> CACHE =
    				new HashMap<IssuerAndSerialNumber, X509Certificate>();
    private static final Map<IssuedCertificateIdentifier, X509Certificate> transactionCACHE =
    				new HashMap<IssuedCertificateIdentifier, X509Certificate>();
    private long serialCounter = 1;
	private static boolean includeCACertInEnrollResponse = false;
    
    private X509Certificate raCert = null;
	private PrivateKey raPrivKey = null;
    
	private X509Certificate caCert = null;
	private PrivateKey caPrivKey = null;	// This will only be set during testing
	private X509Certificate caCertNext = null;
	private IssuerAndSerialNumber caIdentifier = null;
	private X509CRL caCrl = null;
	private String challenge = null;

	/*
	 * Reset all PKI members to null.
	 */
	private void resetPKI() {
    	caCert = null;
    	caPrivKey = null;
    	caCertNext = null;
    	caIdentifier = null;
    	caCrl = null;
    	raCert = null;
    	raPrivKey = null;
    	challenge = null;
	}
	
	/**
	 * Enable/disable the return of the CA certificate with an enroll response.
	 * @param enable	The enable state, default is false.
	 */
	public static void setIncludeCACertInEnrollResponse(boolean enable) {
		includeCACertInEnrollResponse = enable;
	}
	
	/**
	 * Get the challenge password from a certificate signing request.
	 * @param csr	The certificate signing request.
	 * @return		The challenge password or null if none exists.
	 */
    public static String getPassword(PKCS10CertificationRequest csr) {
        Attribute[] attrs = csr.getAttributes();
        for (Attribute attr : attrs) {
            if (attr.getAttrType().equals(
                    PKCSObjectIdentifiers.pkcs_9_at_challengePassword)) {
                DERPrintableString password = (DERPrintableString) attr
                        .getAttrValues().getObjectAt(0);
                return password.getString();
            }
        }
        return null;
    }
    
	/**
	 * Check the identifier against the certificate common name. A null
	 * or empty identifier will always return true.
	 * @param ca			A CA root certificate
	 * @param identifier	The identifying common name (CN).
	 * @return				True if the certificate is valid.
	 */
	public static boolean isValidIssuerIdentifier(X509Certificate ca, String identifier) {
		if (identifier != null && (identifier.length() != 0)) {
			return identifier.equals(ca.getIssuerX500Principal().toString());
		}
		return true;
	}

    /**
     * Default constructor. 
     */
    public MdmScepServlet() {
        super();
    }
    
    /**
     * Check the challenge response password.
     * @param csr	The certificate signing request.
     * @return		True if the csr can be signed.
     */
    private boolean verifyChallengePassword(PKCS10CertificationRequest csr) {
    	String challengeResponse = getPassword(csr);
    	if (challenge == null && challengeResponse == null) {
    		return true;
    	} else if (challenge != null && csr != null) {
    		return challenge.equals(challengeResponse);
    	}
    	return false;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		try {
			MdmServiceProperties.Initialize(config.getServletContext());
			return;
		} catch (Exception e) {
			LOG.error("Cannot initialize MdmServiceProperties");
		}
		throw new ServletException();
	}
    
    /**
     * Initialize the servlet. This is called in service function.
     * @param ca			The certificate authority - this must be a root
     * 						certificate.
     * @param caNext		The certificate authority replacement if ca is
     * 						about to expire.
     * @param iasn			The iasn for the certificate.
     * @param oneTimePasswd	One time password for this session.
     * @throws CertificateEncodingException
     */
    public void init(X509Certificate ca, X509Certificate caNext, X509CRL crl,
    				PrivateKey caPriv, IssuerAndSerialNumber caIasn,
    				X509Certificate ra, PrivateKey raPriv,
    				String challengeResponse) throws GeneralSecurityException {
    	LOG.debug("Restoring MDM session where identifier={}", toString());
    	caCert = ca;
    	caPrivKey = caPriv;
    	caCertNext = caNext;
    	caCrl = crl;
    	caIdentifier = caIasn;
    	raCert = ra;
    	raPrivKey = raPriv;
    	challenge = challengeResponse;
    	if (caCert == null || caIdentifier == null || challenge == null ||
    			(caPrivKey == null && (raCert == null || raPrivKey == null)))
    		throw new GeneralSecurityException();
    }
    
    /**
     * Get a unique key which identifies the certificate.
     * @param cert
     * @return
     */
    public static IssuerAndSerialNumber getIssuerAndSerialNumber(X509Certificate cert) {
    	X509CertificateHolder holder = null;
		try {
			holder = new X509CertificateHolder(cert.getEncoded());
	    	return new IssuerAndSerialNumber(holder.getIssuer(), holder.getSerialNumber());
		} catch (CertificateEncodingException e) {
			LOG.error("Certificate store corrupted");
		} catch (IOException e) {
			LOG.error("Certificate store corrupted");
		}
		return null;
    }
	
    /**
     * Add a certificate to the cache.
     * @param iasn	A unique certificate identifier.
     * @param cert
     */
	private synchronized static void putCertificateCache(IssuerAndSerialNumber iasn, X509Certificate cert) {
		CACHE.put(iasn, cert);
	}
	
	/**
	 * Retrieve a certificate from the cache.
	 * @param iasn	A unique certificate identifier.
	 * @return The certificate or null if it could not be found in the store,
	 */
	private synchronized static X509Certificate getCertificateCache(IssuerAndSerialNumber iasn) {
		if (iasn != null)
			return CACHE.get(iasn);
		return null;
	}
	
    /**
     * Add a certificate to the cache.
     * @param iasn	A unique certificate identifier.
     * @param cert
     */
	public static void putCertificate(IssuerAndSerialNumber iasn, X509Certificate cert) {
		CACHE.put(iasn, cert);
	}
	
	/**
	 * Retrieve a certificate from the cache.
	 * @param iasn	A unique certificate identifier.
	 * @return The certificate or null if it could not be found in the store,
	 */
	public static X509Certificate getCertificate(IssuerAndSerialNumber iasn) {
		if (iasn != null)
			return CACHE.get(iasn);
		return null;
	}
	
	/**
	 * Get the certificate chain for a given iasn.
	 * @param iasn	A unique certificate identifier.
	 * @return The certificate chain or null if a complete chain could not be found.
	 */
	public List<X509Certificate> getCertificateChain(IssuerAndSerialNumber iasn) {
		IssuerAndSerialNumber iasnLast = null;
		List<X509Certificate> certs = new LinkedList<X509Certificate>();
		while (iasn != null) {
			X509Certificate c = getCertificate(iasn);
			if (c != null) {
				iasnLast = iasn;
				iasn = getIssuerAndSerialNumber(c);
				certs.add(c);
				// Break at the root certificate in the chain
				if (iasn.equals(caIdentifier) || iasn.equals(iasnLast))
					break;
			} else {
				iasn = null;
			}
		}
		
		if (iasn != null)
			return certs;
		return null;
	}
	
    /**
     * {@inheritDoc}
     */
    @Override
    public void service(ServletRequest req, ServletResponse resp) throws ServletException, IOException {
    	
    	// Have to override since jscep makes the HTTP service request final    	
		resetPKI();
		LOG.debug("MDM Transaction begin");
		if (req instanceof HttpServletRequest && resp instanceof HttpServletResponse) {	
			
			HttpServletRequest httpRequest = (HttpServletRequest) req;
			HttpServletResponse httpResponse = (HttpServletResponse) resp;
			HttpSession session = httpRequest.getSession(false);

			// This has already been checked by the filter but do again
			if (session != null)
			{
				try {
					X509Certificate ca = (X509Certificate)session.getAttribute(CA_CERT);
					IssuerAndSerialNumber iasn = (IssuerAndSerialNumber)session.getAttribute(CA_CERT_IASN);
					X509CRL crl = (X509CRL)session.getAttribute(CA_CERT_CRL);
					
					// Create if first time accessed
					if (ca != null && iasn == null) {
						iasn = getIssuerAndSerialNumber(ca);
						session.setAttribute(CA_CERT_IASN, iasn);
					}
					
					// TODO: get CRL from database
					if (crl == null) {
					}
					
					init(ca, (X509Certificate)session.getAttribute(CA_CERT_NEXT),
						crl, (PrivateKey)session.getAttribute(CA_PRIVKEY), 
						iasn, (X509Certificate)session.getAttribute(RA_CERT), 
						(PrivateKey)session.getAttribute(RA_PRIVKEY), 
						(String)session.getAttribute(SESSION_PASSWD));
					
				} catch(Exception e) {
					resetPKI();
				}

				if (caCert != null && caIdentifier != null && challenge != null) {
					super.service(req, resp);
					return;
				}
			}
			LOG.error("DROP: null session for URI={}", httpRequest.getRequestURI());
			httpResponse.setContentType("text/html");
			httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			resetPKI();
		} else {
			LOG.error("service unknown");
			throw new ServletException();
		}
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    protected List<X509Certificate> doGetCaCertificate(String identifier) {
		LOG.debug("GetCaCertificate identifier=[{}]", identifier);
    	if (caCert != null && isValidIssuerIdentifier(caCert, identifier)) {
    		LOG.debug("GetCaCertificate success");
    		if (raCert == null)
    			return Collections.singletonList(caCert);
    		
    		ArrayList<X509Certificate> alist = new ArrayList<X509Certificate>(2);
    		// Order is important - CA first
    		alist.add(caCert);
    		alist.add(raCert);
    		return alist;
    	}
    	return Collections.emptyList();
    }

    /**
     * {@inheritDoc}
     */
	@Override
	protected List<X509Certificate> getNextCaCertificate(String identifier)
			throws Exception {
        // When a CA certificate is about to expire, clients need to retrieve
        // the CA's next CA certificate (i.e. the roll-over certificate).
    	if (caCertNext != null && isValidIssuerIdentifier(caCertNext, identifier)) {
			return Collections.singletonList(caCertNext);
    	}
    	return Collections.emptyList();
	}

    /**
     * {@inheritDoc}
     */
	@Override
	protected Set<Capability> doCapabilities(String identifier)
			throws Exception {
		LOG.debug("doCapabilities received");
		if (caCertNext == null)
			return EnumSet.of(Capability.SHA_1, Capability.POST_PKI_OPERATION);
		return EnumSet.of(Capability.SHA_1, Capability.POST_PKI_OPERATION, 
					Capability.GET_NEXT_CA_CERT);
	}

    /**
     * {@inheritDoc}
     */
	@Override
	protected List<X509Certificate> doGetCert(X500Name issuer, BigInteger serial)
			throws Exception {
		
		IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(issuer, serial);

		LOG.debug("Searching cache for {}, {}", iasn.getName(), iasn.getSerialNumber());

		List<X509Certificate> chain = getCertificateChain(iasn);
		if (chain != null) {
			return chain;
		}
		throw new OperationFailureException(FailInfo.badCertId);
	}

    /**
     * {@inheritDoc}
     */
	@Override
	protected List<X509Certificate> doGetCertInitial(X500Name issuer,
			X500Name subject, TransactionId transId) throws Exception {
		IssuedCertificateIdentifier ias = new IssuedCertificateIdentifier(issuer, subject, transId);
		X509Certificate cert = transactionCACHE.get(ias);
		if (cert != null)
			return Collections.singletonList(cert);
			
		return Collections.emptyList();
	}

    /**
     * {@inheritDoc}
     */
	@Override
	protected X509CRL doGetCrl(X500Name issuer, BigInteger serial)
			throws Exception {
		if (caIdentifier.equals(new IssuerAndSerialNumber(issuer, serial))) {
			return caCrl;
		}
		return null;
	}

	/*
	 * doEnroll helper.
	 */
	private X509Certificate generateCertificate(PublicKey pubKey,
			X500Name subject, X500Name issuer, BigInteger serial,
			ASN1Encodable[] subjectAltName) throws Exception {
		
	    Calendar cal = GregorianCalendar.getInstance();
	    cal.set(Calendar.MILLISECOND, 0);
	    cal.set(Calendar.SECOND, 0);
	    cal.add(Calendar.MINUTE, -1);
	    Date notBefore = cal.getTime();
	    cal.add(Calendar.YEAR, 5);
	    Date notAfter = cal.getTime();

	    JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
	            issuer, serial, notBefore, notAfter, subject, pubKey);
	    
	    builder.addExtension(X509Extension.basicConstraints, false, new BasicConstraints(false));
	    if (subjectAltName != null)
	    	builder.addExtension(X509Extension.subjectAlternativeName, true, new DERSequence(subjectAltName));

	    ContentSigner signer;
	    try {
	        signer = new JcaContentSignerBuilder("SHA1withRSA")
	        			.setProvider(BC).build(caPrivKey);
	    } catch (OperatorCreationException e) {
	        throw new Exception(e);
	    }
	    X509CertificateHolder holder = builder.build(signer);
	    return new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
	}
	
	private BigInteger getSerial() {
		++serialCounter;
		return BigInteger.valueOf(serialCounter);
	}
	
	/*
	 * doEnroll helper.
	 */
	private X509Certificate generateCertificate2(PKCS10CertificationRequest csr,
			ASN1Encodable[] subjectAltName) throws Exception {

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
	    
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, getSerial(), notBefore, notAfter, subject, subjectKeyId);
    
        BcX509ExtensionUtils extUtils = new BcX509ExtensionUtils();
	    builder.addExtension(X509Extension.basicConstraints, false, new BasicConstraints(false));	    
	    builder.addExtension(X509Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectKeyId));
	    builder.addExtension(X509Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caHolder));
	    builder.addExtension(X509Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature|KeyUsage.keyEncipherment));
	    if (subjectAltName != null)
	    	builder.addExtension(X509Extension.subjectAlternativeName, true, new DERSequence(subjectAltName));
	    
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
	
    /**
     * {@inheritDoc}
     */
	@Override
	protected List<X509Certificate> doEnrol(
			PKCS10CertificationRequest csr,
			TransactionId transId) throws Exception {
		if (caCert != null) {
	        try {
	        	X509CertificateHolder caHolder = new JcaX509CertificateHolder(caCert);
	            X500Name subject = X500Name.getInstance(csr.getSubject());
	            X500Name issuer = X500Name.getInstance(caHolder.getSubject());
	            ASN1Encodable[] subjectAltName = null;
	            
	            LOG.debug(subject.toString());
	            if (!verifyChallengePassword(csr)) {
	                String password = getPassword(csr);
	            	if (password == null)
	            		LOG.debug("Invalid password=null");
	            	else
	            		LOG.debug("Invalid password={}", password);
	                throw new OperationFailureException(FailInfo.badRequest);
	            }
	            
	            Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);	            
	            for (Attribute a : attributes) {
	            	if (a.getAttrType().equals(Extension.subjectAlternativeName)) {
	            		subjectAltName = a.getAttributeValues();
	            	}
	            }
	            
	            PublicKey pubKey = CertificationRequestUtils.getPublicKey(csr);
	            //X509Certificate cert = generateCertificate(pubKey, subject, issuer, getSerial(), subjectAltName);
	            X509Certificate cert = generateCertificate2(csr, subjectAltName);
	
	            //LOG.debug("Issuing {}", cert);
	            IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(issuer, cert.getSerialNumber());
	            CACHE.put(iasn, cert);
	            transactionCACHE.put(new IssuedCertificateIdentifier(issuer, subject, transId), cert);

	            if (includeCACertInEnrollResponse) {
		    		ArrayList<X509Certificate> alist = new ArrayList<X509Certificate>(2);
		    		// Order is important - CA first
		    		alist.add(cert);
		    		alist.add(caCert);
		    		return alist;	            	
	            }

	            return Collections.singletonList(cert);
	            
	        } catch (Exception e) {
	            LOG.debug("Error in enrollment", e);
	            throw new OperationFailureException(FailInfo.badRequest);
	        }
		} else {
			return Collections.emptyList();
		}
	}

    /**
     * {@inheritDoc}
     */
	@Override
	protected PrivateKey getRecipientKey() {
		if (raPrivKey != null && raCert != null)
			return raPrivKey;
		return caPrivKey;
	}

    /**
     * {@inheritDoc}
     */
	@Override
	protected X509Certificate getRecipient() {
		if (raPrivKey != null && raCert != null)
			return raCert;
		return caCert;
	}

    /**
     * {@inheritDoc}
     */
	@Override
	protected PrivateKey getSignerKey() {
		return caPrivKey;
	}

    /**
     * {@inheritDoc}
     */
	@Override
	protected X509Certificate getSigner() {
		return caCert;
	}
}
