package com.mdm.api.rest;

import javax.annotation.PostConstruct;
import javax.servlet.ServletContext;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.DELETE;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.ProduceMime;
import javax.ws.rs.ConsumeMime;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import com.mdm.api.EnrollmentManager;
import com.mdm.api.OperationFailedException;
import com.mdm.api.RegisterParentRequestData;
import com.mdm.scep.RootCertificateAuthorityException;

/** Handler for:
 * - POST:   /register
 * - DELETE: /register/parent-id
 */
@Path("/register")
public class RegistrationHandler {
	// Allows to insert contextual objects into the class, 
	// e.g. , Request, Response, UriInfo
	@Context
	UriInfo uriInfo;
	@Context
	Request request;
	@Context
	Response response;
	@Context
	ServletContext servletContext;
	
	EnrollmentManager enrollManager;

	public RegistrationHandler() {
	}
	
	@PostConstruct
	public void init() {
		
		enrollManager = (EnrollmentManager)servletContext.getAttribute("enrollManager");
        if (enrollManager == null)
        	throw new WebApplicationException();
	}

	// Register a parent device
	@POST
	@ProduceMime({"application/x-pkcs12"})
	@ConsumeMime(MediaType.APPLICATION_JSON)
	public Response registerParentDevice(RegisterParentRequestData data) {		
		// Verify all parameters are present
		if (!data.isComplete()) {
			throw new BadRequestException("Missing fields required for registration.");
		}
		try {
			return Response.ok(enrollManager.registerParentDevice(data)).build();
		} catch (OperationFailedException e) {
			throw new BadRequestException(String.format("Registration failed: CN=%1%s, L=%2$s, ST=%3$s, C=%4$s",
					data.getFriendlyName(), data.getCity(), data.getState(),
					data.getCountry()));			
		}
	}
	
	// Unregister a parent device
	@DELETE @Path("/{parentId: [a-z0-9]*}")
	@ProduceMime({MediaType.TEXT_HTML})
	public String unregisterParentDevice(@PathParam("parentId") String parentId) {
		// TODO: Check SSL authentication credentials
		try {
			if (enrollManager.unregisterParentDevice(parentId)) {
				return new String();
			}
		} catch (RootCertificateAuthorityException e) {
			return String.format("Cannot unregister parent=%1$s", parentId);
		}
		throw new BadRequestException("Invalid parent=" + parentId);
	}
}
