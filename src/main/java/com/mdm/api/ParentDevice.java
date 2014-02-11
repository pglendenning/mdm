package com.mdm.api;

import com.mdm.cert.CertificateAuthority;

public class ParentDevice {
	
	private final String parentId;
	private CertificateAuthority rootCA;

	public ParentDevice(String parentId, CertificateAuthority rootCA) {
		this.parentId = parentId;
		this.rootCA = rootCA;
	}

	String getParentId() {
		return parentId;
	}
	
	CertificateAuthority getRootCertificateAuthority() {
		return rootCA;
	}
}
