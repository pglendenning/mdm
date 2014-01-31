/**
 * 
 */
package com.mdm.scep;

import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;

/**
 * @author paul
 *
 */
public class AwsSimpleDbRootCertificateAuthorityConnector implements
		IRootCertificateAuthorityConnector {
	private AwsSimpleDbRootCertificateAuthorityStore store;
	private X509Certificate	caCert;
	private X509Certificate	raCert;
	private PrivateKey 		raPrivKey;
	private String			objectId;

	/**
	 * 
	 */
	public AwsSimpleDbRootCertificateAuthorityConnector(AwsSimpleDbRootCertificateAuthorityStore store,
				String objectId, X509Certificate ca, X509Certificate ra, PrivateKey raKey) {
		this.caCert = ca;
		this.raCert = ra;
		this.raPrivKey = raKey;
		this.objectId = objectId;
		this.store = store;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IRootCertificateAuthorityStore getStore() {
		return store;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509Certificate getCaCertificate() {
		return caCert;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getObjectId() {
		return objectId;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509Certificate getRaCertificate() {
		return raCert;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PrivateKey getRaPrivateKey() {
		return raPrivKey;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509CRL getCaCRL(Date date) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addCaCRL(Date notBefore, Date notafter, X509CRL crl) {
		// TODO Auto-generated method stub

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509CRL getCaCRL() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public X509CRL getIssuedCRL() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setEnabled(boolean enableState) {
		// TODO Auto-generated method stub

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<IssuerAndSerialNumber> getIssuedList() {
		// TODO Auto-generated method stub
		return null;
	}

}
