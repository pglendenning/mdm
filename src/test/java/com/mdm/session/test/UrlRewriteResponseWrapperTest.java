package com.mdm.session.test;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import javax.servlet.http.HttpServletResponse;

import org.junit.Test;

import com.mdm.session.UrlRewriteResponseWrapper;

public class UrlRewriteResponseWrapperTest {

	@Test
	public void test() {
		// Use mock to get the interface
		HttpServletResponse response = createMock(HttpServletResponse.class);
		UrlRewriteResponseWrapper modifiedResponse = createMockBuilder(UrlRewriteResponseWrapper.class)
				.withConstructor(response).createMock();
		expect(response.encodeURL("/scep/pkiclient.exe?message=ABC&param=DEF")).andReturn("/scep/pkiclient.exe?message=ABC&param=DEF");
		replay(modifiedResponse);
		replay(response);
		modifiedResponse.changeDestinationAgent("/scep/012345", "/scep");
		String URL = modifiedResponse.encodeURL("/scep/pkiclient.exe?message=ABC&param=DEF");
		verify(response);
		verify(modifiedResponse);
		assertTrue(URL.equals("/scep/012345/pkiclient.exe?message=ABC&param=DEF"));
	}
}
