package com.mdm.session.test;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import org.junit.Test;

import javax.servlet.http.HttpServletRequest;

import com.mdm.session.UrlRewriteRequestWrapper;

public class UrlRewriteRequestWrapperTest {

	@Test
	public void test() {
		
		// Use mock to get the interface
		HttpServletRequest request = createMock(HttpServletRequest.class);
		UrlRewriteRequestWrapper modifiedRequest = createMockBuilder(UrlRewriteRequestWrapper.class)
				.withConstructor(request).createMock();	
		expect(request.getRequestURI()).andReturn("/scep/012345/pkiclient.exe?message=ABC&param=DEF");
		expect(request.getRequestURL()).andReturn(new StringBuffer("http://some.domain/scep/012345/pkiclient.exe?message=ABC&param=DEF"));
		replay(modifiedRequest);
		replay(request);
		modifiedRequest.changeDestinationAgent("/scep/012345", "/scep");
		String requestURI = modifiedRequest.getRequestURI();
		String requestURL = modifiedRequest.getRequestURL().toString();
		verify(request);
		verify(modifiedRequest);
		assertTrue(requestURI.equals("/scep/pkiclient.exe?message=ABC&param=DEF"));
		assertTrue(requestURL.equals("http://some.domain/scep/pkiclient.exe?message=ABC&param=DEF"));
	}
}
