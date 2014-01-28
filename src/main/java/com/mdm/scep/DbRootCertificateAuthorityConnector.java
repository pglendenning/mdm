package com.mdm.scep;

import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class DbRootCertificateAuthorityConnector implements 
			IRootCertificateAuthorityConnector {
	
	private LinkedList<IssuerAndSerialNumber> issued;
	private DbRootCertificateAuthorityStore store;
	private boolean			enabled;
	private X509Certificate	caCert;
	private X509Certificate	raCert;
	private PrivateKey 		raPrivKey;

	
	public DbRootCertificateAuthorityConnector(DbRootCertificateAuthorityStore dbStore,
			X509Certificate ca, X509Certificate ra,
			PrivateKey raKey, boolean enabledState) {
		store = dbStore;
		caCert = ca;
		raCert = ra;
		raPrivKey = raKey;
		enabled = enabledState;
	}
	
	@Override
	public IRootCertificateAuthorityStore getStore() {
		return store;
	}
	

    /**
     * {@inheritDoc}
     */
	@Override
	public X509Certificate getCaCertificate() {
		// return a deep copy
        try {
			return new JcaX509CertificateConverter()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).
				getCertificate(new X509CertificateHolder(caCert.getEncoded()));
		} catch (Exception e) {
		}
        return null;
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public X509Certificate getRaCertificate() {
		// return a deep copy
        try {
			return new JcaX509CertificateConverter()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).
				getCertificate(new X509CertificateHolder(raCert.getEncoded()));
		} catch (Exception e) {
		}
        return null;
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public PrivateKey getRaPrivateKey() {
		// TODO: return a deep copy
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
		return enabled;
	}
	
    /**
     * {@inheritDoc}
     */
	@Override
	public void setEnabled(boolean enableState) {
		enabled = enableState;
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public List<IssuerAndSerialNumber> getIssuedList() {
		return issued;
	}

	@Override
	public String getObjectId() {
		// TODO Auto-generated method stub
		return null;
	}

}
