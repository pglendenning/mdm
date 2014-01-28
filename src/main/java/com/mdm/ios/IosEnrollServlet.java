package com.mdm.ios;

import com.mdm.utils.*;
import com.dd.plist.PropertyListParser;
import com.dd.plist.NSObject;
import com.dd.plist.NSDictionary;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Servlet implementation class EnrollServlet
 */
@WebServlet(description = "Enrolls an iOS device in MDM", urlPatterns = { "/iosenroll", "/profile" })
public class IosEnrollServlet extends IosPayloadServlet {
    
	private static final Logger LOG = LoggerFactory.getLogger(IosEnrollServlet.class);
	private static final long serialVersionUID = 1L;
	private CMSSignedDataGenerator generator = null;
	
    
    /**
     * @see HttpServlet#HttpServlet(
     */
    public IosEnrollServlet() {
        super();
        // TODO Auto-generated constructor stub
    }

	/* (non-Javadoc)
	 * @see com.mdm.ios.IosPayloadServlet#init(javax.servlet.ServletConfig)
	 */
	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		/*
		ServletContext context = config.getServletContext();
		InputStream is = context.getResourceAsStream(KEYSTORE);
		try {
			KeyStore keystore = PKCS7Signer.loadKeyStore(is);
	        generator = PKCS7Signer.setUpProvider(keystore);
	        is.close();
	        return;
		} catch(Exception e) {
			LOG.error("Cannot create PKCS7Signer.");
		}
		*/
		throw new ServletException();
	}
	
	/*
	 * Starts the enrollment process. HTTP GET.
	 */
	protected void doEnrollPhase1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		BasicNonceGenerator gen = new BasicNonceGenerator();
		StringBuffer url = request.getRequestURL();
		url.delete(url.lastIndexOf("iosenroll"), url.length());
		url.append("profile");
		LOG.debug("Phase2 URL=" + url.toString());
		IosEnrollPayload payload = new IosEnrollPayload(url.toString(), gen.createNonce());
		String content = payload.toXMLPropertyList();
		byte[] msg = null;
		try {
			msg = PKCS7Signer.sign(content.getBytes("UTF-8"), generator);
		} catch (CMSException e) {
			LOG.error("Ios Enroll Phase 1 CMSException message:{}", e.getMessage());
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Pkcs7 signer error");
		} catch (IOException e) {
			LOG.error("Ios Enroll Phase 1 IOException message:{}", e.getMessage());
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Pkcs7 signer error");			
		}
		response.setContentType("application/x-apple-aspen-config");
		response.getOutputStream().write(msg);
	}
	
	/*
	 * Second stage enrollment process. HTTP POST
	 */
	protected void doEnrollPhase2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		InputStream is = request.getInputStream();
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		byte[] buf = new byte[1000];
		for (int nChunk = is.read(buf); nChunk!=-1; nChunk = is.read(buf))
		{
		    os.write(buf, 0, nChunk);
		} 
		
		CMSSignedData signedData = null;
		byte[] content = null;
		try {
			signedData = new CMSSignedData(os.toByteArray());
			content = PKCS7Signer.getContent(signedData);
			if (content == null) {
				response.sendError(HttpServletResponse.SC_MOVED_PERMANENTLY, "/iosenroll");	// go to phase 1
				return;
			}
			CertificateVerificationResult result = PKCS7Verifier.verify(signedData);
			if (!result.isValid()) {
				response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Bad Signature.");			
			} else {
				// TODO: check trust anchor is valid
			}
		} catch (CMSException e) {
			LOG.error("Enroll Phase 2 CMSException message:{}", e.getMessage());
			response.sendError(HttpServletResponse.SC_MOVED_PERMANENTLY, "/iosenroll");	// go to phase 1			
		} catch (CertificateVerificationException e) {
			LOG.error("Enroll Phase 2 CertificateVerificationException message:{}", e.getMessage());
			response.sendError(HttpServletResponse.SC_MOVED_PERMANENTLY, "/iosenroll");	// go to phase 1						
		}
		
		// Decode the response
		String challenge = null;
		String UDID = null;
		String MACADDR = null;
		try {
			NSObject o = PropertyListParser.parse(content);
			IosEnrollResponse r = new IosEnrollResponse((NSDictionary)o);
			challenge = r.getChallenge();
			UDID = r.getUDID();
			MACADDR = r.getMacAddressEN0();
			if (challenge == null || UDID == null || MACADDR == null) {
				LOG.info("Enroll Phase 2 request missing critical data");
				response.sendError(HttpServletResponse.SC_BAD_REQUEST); // bad request
				return;
			}
			// TODO: validate the challenge
		} catch (Exception e) {
			LOG.info("Enroll Phase 2 cannot decode plist response");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		
		// TODO: If we issued this certificate goto to phase 3
		/* http://isaacyang1988.googlecode.com/svn/trunk/Crypt/src/org/bouncycastle/jce/provider/test/X509StoreTest.java
		// Searching for rootCert by subjectDN encoded as byte
		targetConstraints = new X509CertStoreSelector();
		targetConstraints.setSubject(PrincipalUtil.getSubjectX509Principal(rootCert).getEncoded());
		certs = certStore.getMatches(targetConstraints);
		if (certs.size() != 1 || !certs.contains(rootCert))
		{
		    fail("rootCert not found by encoded subjectDN");
		}		 
		*/
		// Create configuration profile
		IosConfigurationPayload cfg = new IosConfigurationPayload();
		cfg.setDisplayName("MDM4ALL Device Enrollment");
		cfg.setDescription("Enrolls a device for management services");
		
		StringBuffer url = request.getRequestURL();
		url.append("/scep/pkiclient.exe");
		LOG.debug("Phase2 URL=" + url.toString());
		IosScepPayload scep = new IosScepPayload(url.toString(), challenge, cfg);
		cfg.setContent(scep);
		
		try {
			String plist = cfg.toXMLPropertyList();
			byte[] msg = PKCS7Signer.sign(plist.getBytes("UTF-8"), generator);
			response.setContentType("application/x-apple-aspen-config");
			response.getOutputStream().write(msg);
		} catch (CMSException e) {
			LOG.error("Enroll Phase 2 cannot build signed IosConfigurationPayload");
			response.sendError(500, "Pkcs7 signer error");
		}		
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		if (generator == null || !MdmServiceProperties.isInitialized()) {
			// Something went wrong during initialization
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Pkcs7 signer not initialized");
			return;
		} else if (!request.isSecure()) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		// TODO: Authenticate
		// CLIENT                                       PHP FRONT END                                            MDM BACKEND
		// ======                                       =============                                            ===========
		// GET https://www.mdm4all.com/startenroll ---> 1. Generate random nonce
		//                                              2. GET https://mdm.solidra.com/enroll/?code=<nonce> ---> 1. Create IosEnrollPayload
		//                                                     could include referrer for OTP                       and set challenge = nonce
		//                                                                                                          and URL = https://mdm.solidra.com/profile.
		//                                                                                                       2. Save nonce in temp storage
		//                                                                                                          This is a one time password
		//     <---------------------------------------    Proxy back to client  <------------------------------ 3. Sign with site SSL certificate
		//                                              1. Content-Type = "application/x-apple-aspen-config"       
		// 
		// POST https://mdm.solidra.com/profile ---------------------------------------------------------------> 1. Verify request signature is apple.com.
		// Sends device attributes and challenge                                                                 2. Verify challenge is nonce
		// as specified in IosEnrollPayload                                                                      3. Create SCEP payload
		//     <------------------------------------------------------------------------------------------------    URL = https://mdm.solidra.com/scep
		//                                                                                                          challenge - nonce
		String userPath = request.getServletPath();
		if (userPath.equals("/iosenroll"))
			doEnrollPhase1(request, response);
		else
			response.sendError(HttpServletResponse.SC_FORBIDDEN);
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		if (generator == null || !MdmServiceProperties.isInitialized()) {
			// Something went wrong during initialization
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Pkcs7 signer not initialized");
			return;
		} else if (!request.isSecure()) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		String userPath = request.getServletPath();
		if (userPath.equals("/profile"))
			doEnrollPhase2(request, response);
	}

}
