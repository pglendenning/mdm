package com.mdm.cert.scep;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;
import com.mdm.session.UrlRewriteFilter;

/**
 * Servlet Filter implementation class ScepUrlRewriteFilter
 */
@WebFilter(description = "Removes the OTP from the url and forwards to the scep or ra handler.", urlPatterns = { "/scep/*", "/ra/*" })
public class ScepUrlRewriteFilter extends UrlRewriteFilter {
	
	/**
	 * @see Filter#init(FilterConfig)
	 */
	@Override
	public void init(FilterConfig fConfig) throws ServletException {
		addEndpoint("/scep/pkiclient[.]exe.*");
		addEndpoint("/ra/.*");
	}
}
