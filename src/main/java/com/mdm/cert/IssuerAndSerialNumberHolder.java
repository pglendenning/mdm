/**
 * 
 */
package com.mdm.cert;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Helper class to extract IssuerAndSerialNumber and convert it to a string.
 * @author paul
 */
public class IssuerAndSerialNumberHolder {

	private IssuerAndSerialNumber iasn;
	/**
	 * 
	 */
	public IssuerAndSerialNumberHolder(IssuerAndSerialNumber iasn) {
		this.iasn = iasn;
	}

	public IssuerAndSerialNumberHolder(X509Certificate cert) {
		iasn = null;
		try { 
			X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
			IssuerAndSerialNumber _iasn = new IssuerAndSerialNumber(holder.getIssuer(), holder.getSerialNumber());
			this.iasn = _iasn;
		} catch (Exception e) {
		}
	}
	
	/**
	 * Get the issuer and serial number
	 * @return	The issuer and serial number.
	 */
	public IssuerAndSerialNumber getIasn() {
		return iasn;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		if (iasn == null)
			return "null";
		X500Name name = iasn.getName();
		BigInteger serial = iasn.getSerialNumber().getValue();
		return name.toString() + ":" + serial.toString();		
	}
	
	public boolean isValid() {
		return iasn != null;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        IssuerAndSerialNumberHolder other = (IssuerAndSerialNumberHolder)o;
        return (other.isValid() && isValid() && other.getIasn().equals(iasn)) || 
        		(!other.isValid() && !isValid());
	}
}
