package com.mdm.api;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * Data binding for POST: /register
 * @author Paul Glendenning
 */
@XmlRootElement
public class RegisterParentRequestData {
	
	public String	user;	// user id, this will be the password on the PKCS12 container
	public String	name;	// friendly name
	public String	city;	// X500Name L
	public String	state;	// X500Name ST
	public String	country;// X500Name C
	
	public RegisterParentRequestData() {
		// Required for beans
	}
	
	public RegisterParentRequestData(String user, String name, String city, String state, String country) {
		this.city = city;
		this.country = country;
		this.state = state;
		this.user = user;
		this.name = name;
	}
	
	/**
	 * Get the country.
	 * @return	The X500 country part of the distinguished name.
	 */
	public String getCountry() {
		return country;
	}
	
	/**
	 * Get the state.
	 * @return	The X500 state part of the distinguished name.
	 */
	public String getState() {
		return state;
	}
	
	/**
	 * Get the location/city.
	 * @return	The X500 location part of the distinguished name.
	 */
	public String getCity() {
		return city;
	}
	
	/**
	 * Get the common name.
	 * @return	The X500 CN part of the distinguished name.
	 */
	public String getFriendlyName() {
		return name;
	}
	
	/**
	 * Get the user-id for the parse.com object.
	 * @return	A parse.com user-id string.
	 */
	public String getUserId() {
		return user;
	}
	
	/**
	 * Test if the data is complete.
	 * @return	True if there are no missing parameters.
	 */
	public boolean isComplete() {
		return city != null && !city.isEmpty() && country != null &&
			   !country.isEmpty() && state != null && !state.isEmpty() &&
				name != null && !name.isEmpty() &&
				user != null && !user.isEmpty();
	}

	@Override
	public boolean equals(Object o) {				
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		RegisterParentRequestData that = (RegisterParentRequestData) o;
	
		if (user != null ? !user.equals(that.user) : that.user != null) return false;
		if (name != null ? !name.equals(that.name) : that.name != null) return false;
		if (country != null ? !country.equals(that.country) : that.country != null) return false;
		if (city != null ? !city.equals(that.city) : that.city != null) return false;
		if (state != null ? !state.equals(that.state) : that.state != null) return false;
	
		return true;
	}
	
	@Override
	public int hashCode() {
		int code = 0;
		if (user != null) code ^= user.hashCode();
		if (name != null) code ^= name.hashCode();
		if (country != null) code ^= country.hashCode();
		if (state != null) code ^= state.hashCode();
		return code;
	}
}
