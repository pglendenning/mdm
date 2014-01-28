package com.mdm.api;

import com.mdm.scep.RootCertificateAuthority;

public class ParentDevice {
	
	private final String parentId;
	private RootCertificateAuthority rootCA;

	public ParentDevice(String parentId, RootCertificateAuthority rootCA) {
		this.parentId = parentId;
		this.rootCA = rootCA;
	}

	String getParentId() {
		return parentId;
	}
	
	RootCertificateAuthority getRootCertificateAuthority() {
		return rootCA;
	}
}
