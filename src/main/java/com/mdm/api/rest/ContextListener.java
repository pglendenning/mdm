package com.mdm.api.rest;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mdm.cert.ICertificateAuthorityStore;
import com.mdm.cert.scep.EnrollmentManager;
import com.mdm.utils.MdmServiceKey;
import com.mdm.utils.MdmServiceProperties;

public final class ContextListener implements ServletContextListener {
	private static final Logger LOG = LoggerFactory.getLogger(ContextListener.class);
	private ServletContext context = null;
	
	public void contextInitialized(ServletContextEvent event) {
		
		EnrollmentManager enrollManager = null;
		
		context = event.getServletContext();
		try {
			MdmServiceProperties.Initialize(context);
			enrollManager = new EnrollmentManager((ICertificateAuthorityStore)
						MdmServiceProperties.constructObject(MdmServiceKey.rootCertificateAuthorityStore));
		    context.setAttribute("enrollManager", enrollManager);
		} catch (Exception e) {
			LOG.error("Couldn’t create EnrollmentManager: {}" + e.getMessage());
		}
	}
	
	public void contextDestroyed(ServletContextEvent event) {
	    context = event.getServletContext();
	    // EnrollmentManager enrollManager = (EnrollmentManager) context.getAttribute("enrollManager");
	    // TODO: Dan do I need to close the db connection?
	    context.removeAttribute("enrollManager");
	}
}