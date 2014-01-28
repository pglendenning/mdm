package com.mdm.api;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * Data binding for POST: /enroll/parent-id
 * @author Paul Glendenning
 */
@XmlRootElement
public class EnrollDeviceRequestData {
	private String name;	// Friendly name to associate with a child device

	public EnrollDeviceRequestData() {
		// TODO Auto-generated constructor stub
	}
	
	/**
	 * Check if the name is valid
	 */
	public boolean isValidName() {
		return name != null && !name.isEmpty() && name.matches("[\\d\\w ]+");
	}
	
	/**
	 * Get the friendly name.
	 * @return	A string containing the friendly name.	
	 */
	public String getName() {
		return name;
	}

	@Override
	public boolean equals(Object o) {				
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		EnrollDeviceRequestData that = (EnrollDeviceRequestData) o;
		return name != null ? name.equals(that.name) : that.name == null;
	}
	
	@Override
	public int hashCode() {
		int code = 0;
		if (name != null) code ^= name.hashCode();
		return code;
	}
}
