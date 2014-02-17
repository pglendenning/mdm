package com.mdm.api.rest;

import java.security.cert.X509Certificate;

import javax.annotation.PostConstruct;
import javax.servlet.ServletContext;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.ConsumeMime;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.ProduceMime;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import javax.xml.bind.JAXBElement;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.mdm.api.EnrollDeviceRequestData;
import com.mdm.api.EnrollDeviceResponseData;
import com.mdm.api.EnrollStatusResponseData;
import com.mdm.api.EnrolledDevicesResponseData;
import com.mdm.api.EnrollmentHolder;
import com.mdm.api.InternalErrorException;
import com.mdm.api.InvalidObjectIdException;
import com.mdm.api.OperationFailedException;
import com.mdm.api.OperationNotAllowedException;
import com.mdm.api.EnrollmentManager;
import com.mdm.cert.AwsCertificateAuthorityStore;

/** Handler for:
 * - POST:   /enroll/parent-id
 * - DELETE: /enroll/parent-id
 */
@Path("/enroll")
public class EnrollmentHandler {

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

	public EnrollmentHandler() {
		// TODO Auto-generated constructor stub
	}

	// For testing.
	public void setEnrollmentManager(EnrollmentManager mgr) {
		enrollManager = mgr;
	}
	
	@PostConstruct
	public void init() {
		if (servletContext != null)
			enrollManager = (EnrollmentManager)servletContext.getAttribute("enrollManager");
		else
			setEnrollmentManager(new EnrollmentManager(new AwsCertificateAuthorityStore()));
        if (enrollManager == null)
        	throw new WebApplicationException();
	}

	// Enroll a child device
	@POST @Path("/{parentId: [a-z0-9]*}")
	@ProduceMime({MediaType.APPLICATION_JSON})
	@ConsumeMime({MediaType.APPLICATION_JSON})
	public Response startEnrollDevice(@PathParam("parentId") String parentId, JAXBElement<EnrollDeviceRequestData> req) {
		// TODO: Check SSL authentication credentials
		
		EnrollDeviceRequestData ereqData = req.getValue();
		if (!ereqData.isValidName()) {
			throw new BadRequestException("Invalid characters in name.");
		}
		
		EnrollmentHolder holder = null;		
		EnrollStatusResponseData status = null;
		try {
			holder = enrollManager.startNewEnrollment(parentId, ereqData.getName());
			status = holder.getEnrollStatus();
		} catch (OperationFailedException e) {
			throw new WebApplicationException();
		} catch (InvalidObjectIdException e) {
			throw new NotFoundException("Invalid parent id(" + parentId + ")");						
		}
		
		EnrollDeviceResponseData result = new EnrollDeviceResponseData(holder.getEnrollId(), holder.getEnrollURL(), 
				holder.getSerialNums()[0], holder.getSerialNums()[1],
				status.getOTP(), status.getNextUpdate());
		
		// Set location URI, return json entity with 201 (created) status
		UriBuilder createdURI = uriInfo.getBaseUriBuilder();
		createdURI.path("device");
		createdURI.path(holder.getEnrollId());
		return Response.created(createdURI.build()).entity(Entity.json(result)).build();
	}

	@GET @Path("{parentId: [a-z0-9]*}")
	@ProduceMime({MediaType.APPLICATION_JSON})
	public EnrolledDevicesResponseData getEnrollDevices(@PathParam("parentId") String parentId) {
		
		// TODO: populate instance
		return new EnrolledDevicesResponseData();
	}
	
	@GET @Path("/device/{enrollId: [a-z0-9]*}")
	@ProduceMime({MediaType.APPLICATION_JSON})
	public EnrollStatusResponseData getEnrollStatus(@PathParam("enrollId") String enrollId) {

		EnrollmentHolder holder = enrollManager.getEnrollment(enrollId);
		if (holder == null) {
			throw new NotFoundException("Invalid enrollment identifier.");
		}
		return holder.getEnrollStatus();
	}

	@GET @Path("/ca/{enrollId: [a-z0-9]*}")
	@ProduceMime({"application/pkcs10"})
	public Response getEnrollCSR(@PathParam("enrollId") String enrollId) {
		
		EnrollmentHolder holder = enrollManager.getEnrollment(enrollId);
		if (holder == null) {
			throw new NotFoundException("Invalid enrollment identifier.");
		}
		
		PKCS10CertificationRequest csr = null;
		
		try {
			csr = holder.getCSR();
		} catch (OperationNotAllowedException e) {
			// TODO auto map exceptions to response codes
			throw new NotFoundException("Signing request not available.");
		} catch (InternalErrorException e) {
			throw new WebApplicationException();
		}
		return Response.ok(Entity.entity(csr, "application/pkcs10"))
					.header("Content-Disposition", "attachment; filename=" + holder.getEnrollId() + ".csr")
					.build();
	}
	
	@POST @Path("/ca/{enrollId: [a-z0-9]*}")
	@ConsumeMime({"application/x-x509-ca-cert"})
	public Response doEnrollCSR(@PathParam("enrollId") String enrollId, byte[] encodedCert) {
		
		EnrollmentHolder holder = enrollManager.getEnrollment(enrollId);
		if (holder == null) {
			throw new NotFoundException("Invalid enrollment identifier.");
		}

		X509Certificate cert = null;
        try {
			cert = new JcaX509CertificateConverter()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).
				getCertificate(new X509CertificateHolder(encodedCert));
		} catch (Exception e) {
			throw new BadRequestException("Invalid X509 certificate.");			
		}

        try {
			holder.completeCSR(cert);
		} catch (OperationNotAllowedException e) {
			throw new BadRequestException("No signing request to fulfill.");
		} catch (OperationFailedException e) {
			throw new WebApplicationException();
		} catch (InternalErrorException e) {
			throw new WebApplicationException();
		}

		// TODO: fulfill CSR
		// Set location URI, return empty entity with 201 (created) status
		UriBuilder createdURI = uriInfo.getBaseUriBuilder();
		createdURI.path("device");
		createdURI.path(holder.getEnrollId());
		return Response.created(createdURI.build()).entity(Entity.text(null)).build();
	}
}
