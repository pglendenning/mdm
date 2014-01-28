package com.mdm.api;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * Data binding for POST: /enroll/parent-id
 * @author Paul Glendenning
 */
@XmlRootElement
public class EnrollDeviceResponseData {
	public String enrollId;		// unique enrollment id string
	public String enrollURL;	// enrollment url to send to child
	public long[] serialNums;	// 2 x serial numbers
	public String otp;			// 6 digit one-time password
	public int    nextUpdate;	// time in seconds until next update

	public EnrollDeviceResponseData(String enrollId, String enrollURL, long serialNum1, long serialNum2, String otp, int nextUpdate) {
		this.enrollId = enrollId;
		this.enrollURL = enrollURL;
		this.serialNums = new long[2];
		this.serialNums[0] = serialNum1;
		this.serialNums[1] = serialNum2;
		this.otp = otp;
		this.nextUpdate = nextUpdate;
	}
	
	@Override
	public boolean equals(Object o) {				
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		EnrollDeviceResponseData that = (EnrollDeviceResponseData) o;
	
		if (enrollId != null ? !enrollId.equals(that.enrollId) : that.enrollId != null) return false;
		if (enrollURL != null ? !enrollURL.equals(that.enrollURL) : that.enrollURL != null) return false;
		if (serialNums != null ? !serialNums.equals(that.serialNums) : that.serialNums != null) return false;
		if (otp != null ? !otp.equals(that.otp) : that.otp != null) return false;
		return nextUpdate == that.nextUpdate;
	}
	
	@Override
	public int hashCode() {
		int code = 0;
		if (enrollId != null) code ^= enrollId.hashCode();
		if (enrollURL != null) code ^= enrollURL.hashCode();
		if (serialNums != null) code ^= serialNums.hashCode();
		return code ^= new Integer(nextUpdate).hashCode();
	}
}
