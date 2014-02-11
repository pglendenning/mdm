package com.mdm.session;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

public class UrlRewriteResponseWrapper extends HttpServletResponseWrapper {
	private String originalDestination, newDestinationAgent;
	
	public UrlRewriteResponseWrapper(HttpServletResponse response) {
		super(response);
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public String encodeURL(String url) {
		String originalURL = super.encodeURL(url);
		StringBuffer newURL = new StringBuffer();
		int k = originalURL.indexOf(newDestinationAgent);
		if (k < 0)
			return originalURL;	
		newURL.append(originalURL.substring(0, k));
		newURL.append(originalDestination);
		newURL.append(originalURL.substring(k + newDestinationAgent.length(), originalURL.length()));
		return newURL.toString();
	}
	
    /**
     * {@inheritDoc}
     */
	@Override
	public String encodeRedirectURL(String url) {
		return encodeURL(url);
	}
	
	/**
	 * Change the original destination agent/queue manager set in the request by the
	 * HTTP client (or a previous filter) to a new destination agent/queue manager.
	 * 
	 * @param originalDestination
	 * @param newDestination
	 */
	public void changeDestinationAgent(String originalDestination, String newDestination) {
		this.originalDestination = originalDestination;
		this.newDestinationAgent = newDestination;
	}	
}
