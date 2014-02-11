package com.mdm.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class UrlRewriteRequestWrapper extends HttpServletRequestWrapper {
	private String originalDestination, newDestinationAgent;
	
	/*
	 * Constructor
	 */
	public UrlRewriteRequestWrapper(HttpServletRequest request) {
		super(request);
	}
	
    /**
     * {@inheritDoc}
     */
	@Override
	public String getRequestURI() {
		String originalURI = super.getRequestURI();		
		StringBuffer newURI = new StringBuffer();
		int pos = originalURI.indexOf(originalDestination);
		
		newURI.append(originalURI.substring(0, pos));
		newURI.append(newDestinationAgent);
		newURI.append(originalURI.substring(pos + originalDestination.length(), originalURI.length()));		
		return newURI.toString();
	}
	
    /**
     * {@inheritDoc}
     */
	@Override
	public StringBuffer getRequestURL() {
		String originalURL = super.getRequestURL().toString();
		StringBuffer newURL = new StringBuffer();
		int pos = originalURL.indexOf(originalDestination);

		newURL.append(originalURL.substring(0, pos));
		newURL.append(newDestinationAgent);
		newURL.append(originalURL.substring(pos + originalDestination.length(), originalURL.length()));
		return newURL;		
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
