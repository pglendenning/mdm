package com.mdm.api;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * Data binding for GET: /enroll/parent-id
 * @author Paul Glendenning
 */
@XmlRootElement
public class EnrolledDevicesResponseData {
	
	@XmlRootElement
	public class EnrolledDeviceData {
		public String enrollId;
		public String name;
		
		@Override
		public boolean equals(Object o) {				
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			EnrolledDeviceData that = (EnrolledDeviceData) o;
		
			if (enrollId != null ? !enrollId.equals(that.enrollId) : that.enrollId != null) return false;
			if (name != null ? !name.equals(that.name) : that.name != null) return false;
			return true;
		}
		
		@Override
		public int hashCode() {
			int code = 0;
			if (enrollId != null) code ^= enrollId.hashCode();
			if (name != null) code ^= name.hashCode();
			return code;
		}
	}
	
	public EnrolledDeviceData[] enrolled;
	public EnrolledDeviceData[] pending;

	public EnrolledDevicesResponseData() {
		// TODO Auto-generated constructor stub
	}
	
	@Override
	public boolean equals(Object o) {				
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		EnrolledDevicesResponseData that = (EnrolledDevicesResponseData) o;
	
		if (enrolled != null ? !enrolled.equals(that.enrolled) : that.enrolled != null) return false;
		if (pending != null ? !pending.equals(that.pending) : that.pending != null) return false;
		return true;
	}
	
	@Override
	public int hashCode() {
		int code = 0;
		if (enrolled != null) code ^= enrolled.hashCode();
		if (pending != null) code ^= pending.hashCode();
		return code;
	}
}
