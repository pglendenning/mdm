package com.mdm.session.test;

import static org.easymock.EasyMock.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.fail;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.mdm.cert.X509CertificateGenerator;
import com.mdm.cert.scep.MdmScepServlet;
import com.mdm.session.UrlRewriteFilter;
import com.mdm.session.UrlRewriteRequestWrapper;
import com.mdm.session.UrlRewriteResponseWrapper;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/*
 * Unit test for MdmUrlRewriteFilter.
 */
public class UrlRewriteFilterTest {
	
	private HttpServletRequest request = createMock(HttpServletRequest.class);
	private HttpServletResponse response = createMock(HttpServletResponse.class);
	private UrlRewriteFilter filter = new UrlRewriteFilter("[0-9]{6}");
	private HttpSession session = createMock(HttpSession.class);
	private FilterChain chain = createMock(FilterChain.class);
	private KeyFactory fact;
	
	@Before
	public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        try {
        	fact = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        } catch(Exception e) {
        	e.printStackTrace();
        	fail();
        }
	}
	
	@After
	public void tearDown() {
		Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
	}
	
	private X509Certificate getCert() throws Exception {
		// FIXME: should load from PCKS7 so we don't depend on 
		// X509CertificateGenerator.
		PrivateKey caPriv = fact.generatePrivate(
				new RSAPrivateCrtKeySpec(
					new BigInteger("a5226e241a19f5b796ef2326f4f580b1e5cbc05360a7fd94fd8d59013115e077a422beb4904c5e57f0d9827a0da98b337ab8d47a2b24f77d83f9689e9b43af6b23bf39a1e4e87d8ce9f7d68b8dd50ffec1d34b25833848325ed035d3a1ddeaf62fe5a184dec918d7c2e8b89b17b057a9af359280956dc2a393be6e9a04517b25", 16),
					new BigInteger("10001", 16),
					new BigInteger("6ff223507e11532e1e380750858758b340e11b846a65f7d664fcc975b15cef4aac0e91d1be70c7143ec6755960a1ab283eedc5bcfc3a973c9397248141286565d479dd57d9bc01d4dec645dd1ae01590671315ec6f9bcde606707255382fcb363744a8bcda3c7a3c2e4015d450ed4aafb675ae277ddcf0e779165125a84f6681", 16),
					new BigInteger("f8e745cf5388418a0f038b425095aa8ce3cae42764c15d6f91021a0b6fe0746653428ac95c88ce127deae745521805b6a53da780b56c3f4d15f0c88a85a19609", 16),
					new BigInteger("a9d7bc0903893d8116ad8df22e425df382f895d47c0a47d7ea182e9a6221f3d1b27cdfd278960d8cc65699a5c1e5e17197805c9954ff6c37c19a0d9e2241a33d", 16),
					new BigInteger("88181ca9a228ec7d0a7c8b9674ed80d58c701194209941f790b82f797570aaf4902de028fdb9a7c3a0a9e24e9af69b99247cb3abc2872f8d7ca3ad636071dbd1", 16),
					new BigInteger("5f024cb0aa26ba9e1cc68772238882aff6e30245b401b840c33635d3acf39b4601d7b30934e593bcdd32928ed411b97466b0aa9c279d1eb76df8b48772584f6d", 16),
					new BigInteger("e9774efb165c4309e7c7f32603d882d2e8b728887ddb50ee2c2e89591d192b64058699d3251e01348ee24dd23669aec43f1b4e16266950f6268e632242b7d500", 16)));
		PublicKey caPub = fact.generatePublic(
				new RSAPublicKeySpec(
					new BigInteger("a5226e241a19f5b796ef2326f4f580b1e5cbc05360a7fd94fd8d59013115e077a422beb4904c5e57f0d9827a0da98b337ab8d47a2b24f77d83f9689e9b43af6b23bf39a1e4e87d8ce9f7d68b8dd50ffec1d34b25833848325ed035d3a1ddeaf62fe5a184dec918d7c2e8b89b17b057a9af359280956dc2a393be6e9a04517b25", 16),
					new BigInteger("10001", 16)));
		return X509CertificateGenerator.createV1RootCA(caPub, caPriv, 
				1, 2, "CN=Test, O=Mdm4all", null, null);
	}

	private void doReset() {
		reset(request);
		reset(response);
		reset(session);
		reset(chain);
	}
	
	private void doReplay() {
		replay(response);
		replay(request);	
		replay(session);	
		replay(chain);			
	}
	
	private void doVerify() {
		verify(response);
		verify(request);	
		verify(session);	
		verify(chain);			
	}
	
	private void checkDropURIPattern(String uri) throws Exception {
		doReset();
		expect(request.getRequestURI()).andReturn(uri);
		expect(request.getSession(false)).andReturn(session);
		response.setContentType("text/html");
		response.sendError(HttpServletResponse.SC_FORBIDDEN);
		doReplay();
		filter.doFilter(request, response, chain);
		doVerify();
	}
	
	private void checkFwdURIPattern(String uri) throws Exception {
		doReset();
		expect(request.getRequestURI()).andReturn(uri);
		expect(request.getSession(false)).andReturn(session);
		chain.doFilter(request, response);
		doReplay();
		filter.doFilter(request, response, chain);
		doVerify();
	}
	
	private void checkBadOTPURIPattern(String uri) throws Exception {
		doReset();
		expect(request.getRequestURI()).andReturn(uri);
		expect(request.getSession(false)).andReturn(session);
		expect(session.getId()).andReturn("012345");
		response.setContentType("text/html");
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		doReplay();
		filter.doFilter(request, response, chain);
		doVerify();
	}
	
	@Test
	public void testDoFilter() throws Exception {
		try {
			// DROP response due to missing init data
			expect(request.getRequestURI()).andReturn("/scep/012345/pkiclient.exe");
			expect(request.getSession(false)).andReturn(null);
			response.setContentType("text/html");
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			doReplay();
			filter.doFilter(request, response, chain);
	 		doVerify();
			
			// DROP due to null session 
	 		filter.addEndpoint("/scep/pkiclient[.]exe.*");
			filter.init(null);
			doReset();
			expect(request.getRequestURI()).andReturn("/scep/012345/pkiclient.exe");
			expect(request.getSession(false)).andReturn(null);
			response.setContentType("text/html");
			response.sendError(HttpServletResponse.SC_FORBIDDEN);
			doReplay();
			filter.doFilter(request, response, chain);
			doVerify();
			
			// REJECT bad urls
			checkFwdURIPattern("/pkiclient.exe");
			checkFwdURIPattern("/somepath/pkiclient.exe");
			checkDropURIPattern("/scep/pkiclient.exe");
			checkDropURIPattern("/scep");
			checkDropURIPattern("/scep/somepath");
			checkDropURIPattern("/scep/somepath/pkiclient.exe");
			checkDropURIPattern("/scep/0/pkiclient.exe");
			checkDropURIPattern("/scep/01/pkiclient.exe");
			checkDropURIPattern("/scep/012/pkiclient.exe");
			checkDropURIPattern("/scep/0123/pkiclient.exe");
			checkDropURIPattern("/scep/01234/pkiclient.exe");
			checkDropURIPattern("/scep/01234/pkiclient.exe");
			checkDropURIPattern("/scep/01234X/pkiclient.exe");
			
			// REJECT good urls but bad OTP
			checkBadOTPURIPattern("/scep/543210/pkiclient.exe");
			checkBadOTPURIPattern("/scep/999999/pkiclient.exe?message=ABC&param=DEF");
					
			// REJECT no CA
			filter.init(null);
			doReset();
			expect(request.getRequestURI()).andReturn("/scep/012345/pkiclient.exe");
			expect(request.getSession(false)).andReturn(session);
			expect(session.getId()).andReturn("012345");
			expect(session.getAttribute(MdmScepServlet.CA_CERT)).andReturn(null);
			response.setContentType("text/html");
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			doReplay();
			filter.doFilter(request, response, chain);
			doVerify();
			
			// ACCEPT
			doReset();
			X509Certificate caCert = getCert();
			HttpServletRequest ignoreReq = createMock(HttpServletRequest.class);
			HttpServletResponse ignoreResp = createMock(HttpServletResponse.class);
			UrlRewriteRequestWrapper modifiedRequest = createMockBuilder(UrlRewriteRequestWrapper.class)
						.withConstructor(ignoreReq).createMock();
			UrlRewriteResponseWrapper modifiedResponse = createMockBuilder(UrlRewriteResponseWrapper.class)
					.withConstructor(ignoreResp).createMock();
			filter = createMockBuilder(UrlRewriteFilter.class)
						.withConstructor("[0-9]{6}")
						.addMockedMethod("createRequestWrapper")
						.addMockedMethod("createResponseWrapper")
						.createMock();
			expect(request.getRequestURI()).andReturn("/scep/012345/pkiclient.exe?message=ABC&param=DEF");
			expect(request.getSession(false)).andReturn(session);
			expect(session.getId()).andReturn("012345");
			expect(session.getAttribute(MdmScepServlet.CA_CERT)).andReturn(caCert);
			expect(filter.createRequestWrapper(request)).andReturn(modifiedRequest);
			expect(filter.createResponseWrapper(response)).andReturn(modifiedResponse);
			modifiedRequest.changeDestinationAgent("/scep/012345", "/scep");
			modifiedResponse.changeDestinationAgent("/scep/012345", "/scep");
			chain.doFilter(modifiedRequest, modifiedResponse);
			doReplay();
			replay(modifiedResponse);
			replay(modifiedRequest);
			replay(filter);
			replay(ignoreReq);
			filter.addEndpoint("/scep/pkiclient[.]exe.*");
			filter.init(null);
			filter.doFilter(request, response, chain);
			verify(response);
			verify(request);	
			verify(session);	
			verify(chain);			
			verify(modifiedRequest);
			verify(modifiedResponse);
			verify(filter);
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
}
