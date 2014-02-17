/**
 * 
 */
package com.mdm.api;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author paul
 *
 */
@XmlRootElement
public class RegisterParentResponseData {
	
	String	objectId;
	byte[]	pkcs12;

	public RegisterParentResponseData() {
		// Required for beans
	}

	public RegisterParentResponseData(String objectId, byte[] pkcs12) {
		this.objectId = objectId;
		this.pkcs12 = pkcs12;
	}
	
	public String getObjectId() {
		return objectId;
	}
	
	public byte[] getPkcs12() {
		return pkcs12;
	}
}
