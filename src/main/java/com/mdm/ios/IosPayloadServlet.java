package com.mdm.ios;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mdm.utils.MdmServiceProperties;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

/**
 * Servlet implementation class IosPayloadServlet
 */
public class IosPayloadServlet extends HttpServlet {

	private static final Logger LOG = LoggerFactory.getLogger(IosPayloadServlet.class);
	private static final long serialVersionUID = 1L;

	/**
     * @see HttpServlet#init()
	 */
    @Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		try {
			MdmServiceProperties.Initialize(config.getServletContext());
			return;
		} catch (Exception e) {
			LOG.error("Cannot initialize IosPayloadProperties");
		}
		throw new ServletException();
	}

	/**
     * @see HttpServlet#HttpServlet()
     */
    public IosPayloadServlet() {
        super();
    }

}
