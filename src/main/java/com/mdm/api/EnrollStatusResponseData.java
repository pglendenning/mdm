package com.mdm.api;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * Data binding for GET: /enroll/device/enroll-id
 * @author Paul Glendenning
 */
@XmlRootElement
public class EnrollStatusResponseData {
	public static final int DO_NOTHING = 0;
	public static final int DO_CSR = 1;
	public static final int DO_CANCEL = 2;
	private String enrollment;	// Either "active" or "pending"
	private int    action;		// Action code
	private String otp;			// One time password
	private int    nextUpdate;	// Time in seconds to next one-time-password update
	
	public EnrollStatusResponseData(boolean isEnrolled, int action, String otp, int nextUpdate) {
		this.action = action;
		this.otp = otp;
		this.nextUpdate = nextUpdate;
		if (isEnrolled)
			this.enrollment = "active";
		else
			this.enrollment = "pending";
	}
	
	/**
	 * Get the URL the child device should use for enrollment.
	 * @return	The enrollment URL.
	 */
	public String getEnrollmentStatus() {
		return enrollment;
	}
	
	/**
	 * Get the client action code.
	 * @return	An integer action code.
	 */
	public int getActionCode() {
		return action;
	}
	
	/**
	 * Get the 6 digit one time password as a string.
	 * @return
	 */
	public String getOTP() {
		return otp;
	}
	
	/**
	 * Get the time in seconds to the next one-time-password update.
	 * @return	A positive integer time period in seconds.
	 */
	public int getNextUpdate() {
		return nextUpdate;
	}

	@Override
	public boolean equals(Object o) {				
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		EnrollStatusResponseData that = (EnrollStatusResponseData) o;
	
		if (enrollment != null ? !enrollment.equals(that.enrollment) : that.enrollment != null) return false;
		if (otp != null ? !otp.equals(that.otp) : that.otp != null) return false;
		return nextUpdate == that.nextUpdate && action == that.action;
	}
	
	@Override
	public int hashCode() {
		int code = 0;
		if (enrollment != null) code ^= enrollment.hashCode();
		if (otp != null) code ^= otp.hashCode();
		return code ^= new Integer(nextUpdate).hashCode() ^ new Integer(action).hashCode();
	}
}
