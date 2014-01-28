package com.mdm.scep;

import java.io.Serializable;

import org.bouncycastle.asn1.x500.X500Name;
import org.jscep.asn1.IssuerAndSubject;
import org.jscep.transaction.TransactionId;

public final class IssuedCertificateIdentifier implements Serializable {
	
	private static final long serialVersionUID = 1L;
	private IssuerAndSubject issuerAndSubject = null;
	private TransactionId transId = null;
	
	/**
	 * Constructor
	 * @param	ias	The issuer and subject.
	 * @param 	id	The SCEP transaction id.
	 */
	public IssuedCertificateIdentifier(IssuerAndSubject ias, TransactionId id) {
		issuerAndSubject = ias;
		transId = id;
	}
	
	/**
	 * Constructor
	 * @param	issuer	The issuer distinguished name.
	 * @param	subject	The subject distinguished name.
	 * @param 	id		The SCEP transaction id.
	 */
	public IssuedCertificateIdentifier(X500Name issuer, X500Name subject, TransactionId id) {
		issuerAndSubject = new IssuerAndSubject(issuer, subject);
		transId = id;
	}
	
	/**
	 * Get the transaction id part of the identifier.
	 * @return	The SCEP transaction id.
	 */
	public final TransactionId getTransactionId() {
		return transId;
	}

	/**
	 * Get the Issuer and subject part of the identifier.
	 * @return	The issuer and subject.
	 */
	public final IssuerAndSubject getIssuerAndSubject() {
		return issuerAndSubject;
	}
	
    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
    	StringBuffer buf = new StringBuffer();
    	buf.append(issuerAndSubject);
    	buf.append(transId);
    	return buf.toString();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        IssuedCertificateIdentifier ici = (IssuedCertificateIdentifier)o;
        return transId.equals(ici.getTransactionId()) && 
        				issuerAndSubject.equals(ici.getIssuerAndSubject());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return transId.hashCode() ^ issuerAndSubject.hashCode();
    }	
}
