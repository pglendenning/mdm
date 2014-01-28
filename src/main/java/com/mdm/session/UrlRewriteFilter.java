package com.mdm.session;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mdm.scep.MdmScepServlet;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Servlet Filter implementation class UrlRewriteFilter
 */
public class UrlRewriteFilter implements Filter {
	private static final Logger LOG = LoggerFactory.getLogger(UrlRewriteFilter.class);
	
	// URL patterns for forwarding.
	private Pattern acceptPattern = null;
	private Pattern dropPattern = null;
	private List<String> endpoints = null;
	private String sessionIdPattern = "[A-Za-z0-9-_]{32}";

    /**
     * Default constructor. 
     */
    public UrlRewriteFilter() {
        super();
    	endpoints = new LinkedList<String>();
    }

    public UrlRewriteFilter(String pattern) {
        super();
        sessionIdPattern = pattern;
    	endpoints = new LinkedList<String>();
    }
    
	/**
	 * @see Filter#destroy()
	 */
	public void destroy() {
	}
	
	/**
	 * Create a wrapper for the current request. Using function for mocking
	 * in unit tests.
	 */
	public UrlRewriteRequestWrapper createRequestWrapper(HttpServletRequest request) {
		return new UrlRewriteRequestWrapper(request);
	}

	/**
	 * Create a wrapper for the current response. Using function for mocking
	 * in unit tests.
	 */
	public UrlRewriteResponseWrapper createResponseWrapper(HttpServletResponse response) {
		return new UrlRewriteResponseWrapper(response);
	}

	/**
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {	
			//   URL regex                                       ACTION
			//   /scep/sessionid/pkiclient.exe                   Forward to /scep/pkiclient.exe
			//   /scep(/(?!sessionid/pkickilent.exe).*)|/|$)     Not Authorized
			//   else                                            Chain
			//
			//   sessionid is the session id. For each session id and prior to forwarding:
			//   (1) Validate against our session id cache.
			//   (2) Lookup session and add to context.
			
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			HttpServletResponse httpResponse = (HttpServletResponse) response;
			String requestURI = httpRequest.getRequestURI();
			HttpSession session = httpRequest.getSession(false);

			///////////////////////////////////////////////////////////////////
			// Apply DROP rules
			
			if (acceptPattern == null || dropPattern == null) {
				// drop - these should have been created
				LOG.error("DROP no pattern to handle URI={}", requestURI);
				httpResponse.setContentType("text/html");
				httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				return;
			}
			
			if (session == null) {
				LOG.warn("DROP session = null for URI={}", requestURI);
				httpResponse.setContentType("text/html");
				httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
				return;				
			}
			
			///////////////////////////////////////////////////////////////////
			// Apply REJECT rules
			
			Matcher maccept = acceptPattern.matcher(requestURI);
			
			if (!maccept.matches()) {
				Matcher mdrop = dropPattern.matcher(requestURI);
				if (mdrop.matches()) {
					LOG.info("REJECT bad URI={}", requestURI);
					httpResponse.setContentType("text/html");
					httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
					return;
				}
				// else forward
				chain.doFilter(request, response);
				return;
			} else {
				int gcount = maccept.groupCount();
				if (gcount != 4) {
					// Should not happen
					LOG.error("REJECT bad group count {} for URI={}", maccept.groupCount(), requestURI);
					httpResponse.setContentType("text/html");
					httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
					return;
				}
			}
			
			String group2 = maccept.group(2);
			String sessionId = session.getId();
			int code = sessionId.indexOf(group2);
			
			// Session is of format "/jsessionid;=<cluster-ref><random code>"
			if (code < 0 || (code+sessionId.length()) != group2.length()) {
				LOG.info("REJECT invalid OTP URI={}", requestURI);
				httpResponse.setContentType("text/html");
				httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
				return;
			}

			Object ca = null;
			try {
				ca = session.getAttribute(MdmScepServlet.CA_CERT);
			} catch(Exception e) {
				ca = null;
			}
			if (ca == null || !(ca instanceof X509Certificate)) {
				LOG.info("REJECT invalid CA URI={}", requestURI);
				httpResponse.setContentType("text/html");
				httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
				return;				
			}
			
			///////////////////////////////////////////////////////////////////
			// ACCEPT - rewrite URI
			
			StringBuffer originalDestination = new StringBuffer();
			originalDestination.append(maccept.group(1));
			originalDestination.append(maccept.group(2));
			originalDestination.append(maccept.group(3));
			
			UrlRewriteRequestWrapper modifiedRequest = createRequestWrapper(httpRequest);
			UrlRewriteResponseWrapper modifiedResponse = createResponseWrapper(httpResponse);
			modifiedRequest.changeDestinationAgent(originalDestination.toString(), maccept.group(1));
			modifiedResponse.changeDestinationAgent(originalDestination.toString(), maccept.group(1));
			chain.doFilter(modifiedRequest, modifiedResponse);
			
		} else {
			// pass the request along the filter chain
			chain.doFilter(request, response);
		}
	}
	
	/**
	 * Add an endpoint URL spec. This is a path when each directory or base name is a regular
	 * expression with no capture groups. For example /root/scep/pkiclient[.]exe.*
	 * @param ep
	 * @throws ServletException
	 */
	public void addEndpoint(String ep) throws ServletException {
		// cannot special characters
		if (ep.contains("()*?+;")) {
			LOG.error("Illegal characters in endpoint expression");
			throw new ServletException();
		}
		endpoints.add(ep);
	}

	/**
	 * @see Filter#init(FilterConfig)
	 */
	@Override
	public void init(FilterConfig fConfig) throws ServletException {
		// Create our URL filter pattern
		if (endpoints.isEmpty()) {
			LOG.error("Filter initialized with no endpoints");
			throw new ServletException();
		}
		
		// find the last '/' in each endpoint
		StringBuilder sbAccept = new StringBuilder();
		StringBuilder sbDrop = new StringBuilder();
		for (String p : endpoints) {
			int e = p.lastIndexOf('/');
			int b = p.indexOf('/');
			
			if (sbAccept.length() != 0)
				sbAccept.append("|");
			if (sbDrop.length() != 0)
				sbDrop.append("|");
			
			if (e < 0 || (b == e || b != 0)) {
				LOG.error("Invalid url rewrite endpoint path - {}", p);
				throw new ServletException();
			} else {
				// form = "/path/to/endpoint"  <-- "/path/to/sessionid/endpoint"
				//     or "/path/to/endpoint/" <-- "/path/to/endpoint/sessionid/
				sbAccept.append("(");				// group 1
				sbAccept.append(p.substring(b, e));
				sbAccept.append("/)(");				// group 2
				sbAccept.append(sessionIdPattern);
				sbAccept.append(")(/)(");				// group 3
				sbAccept.append(p.substring(e+1));
				sbAccept.append(")");
				sbDrop.append(p.substring(b, e));
				sbDrop.append(".*");
			}
		}

		String accept = sbAccept.toString();
		String drop = sbDrop.toString();
		LOG.debug("Accept pattern = {}", accept);
		LOG.debug("Drop pattern = {}", drop);
		acceptPattern = Pattern.compile(accept);
		dropPattern = Pattern.compile(drop);
	}
}
