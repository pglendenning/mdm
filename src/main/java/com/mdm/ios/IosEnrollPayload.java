package com.mdm.ios;

import com.dd.plist.*;
import com.mdm.utils.MdmServiceProperties;

import java.lang.String;

public class IosEnrollPayload extends IosPayload {
	
	private void initialize(String url, String challenge, IosPayload parent) {
		// Create a profile service payload
		init1();
    	if (parent != null)
    		nsdict.put("PayloadIdentifier", MdmServiceProperties.getProperty("ProfileServiceName")+parent.getUUID());
    	else
    		nsdict.put("PayloadIdentifier", MdmServiceProperties.getProperty("ProfileServiceName"));
		nsdict.put("PayloadType", "Profile Service"); // do not modify
		// strings that show up in UI, customizable
		nsdict.put("PayloadDisplayName", MdmServiceProperties.getProperty("CompanyShortName") + " Profile Service");
		nsdict.put("PayloadDescription", "Install this profile to enroll for secure access to " +
									MdmServiceProperties.getProperty("CompanyLegalName"));
		
		NSDictionary content = new NSDictionary();
		NSArray a = new NSArray(3);
		content.put("URL", url);
		a.setValue(0, new NSString("UDID"));
		a.setValue(1, new NSString("VERSION"));
		a.setValue(2, new NSString("SERIAL"));
		a.setValue(2, new NSString("MAC_ADDRESS_EN0"));
		a.setValue(2, new NSString("PRODUCT"));
		content.put("DeviceAttributes", a);
		
		//"PRODUCT",              // ie. iPhone1,1 or iPod2,1
		//"SERIAL",               // serial number
		//"MAC_ADDRESS_EN0",      // WiFi MAC address
		//"DEVICE_NAME",          // given device name "iPhone"
		// Items below are only available on iPhones
		//"IMEI",
		//"ICCID"
		//"DEVICE_NAME"
		if (challenge != null && !challenge.isEmpty())
		    content.put("Challenge", challenge);
		nsdict.put("PayloadContent", content);
	}
	
	/**
	 * Get the challenge response string.
	 * @return The challenge string or null if none present.
	 */
	String getChallenge() {
    	NSObject c = nsdict.get("PayloadContent");
    	if (c != null) {
    		NSObject o = ((NSDictionary)c).get("Challenge");
    		if (o != null)
    			return (String)o.toJavaObject();
    	}
    	return null;
	}
	
	/**
	 * Get the URL which will be used to download the .mobileconfig
	 * @return The URL or null is none present.
	 */
	String getURL() {
    	NSObject c = nsdict.get("PayloadContent");
    	if (c != null) {
    		NSObject o = ((NSDictionary)c).get("URL");;
    		if (o != null)
    			return (String)o.toJavaObject();
    	}
    	return null;
	}
	
	/**
	 * Get the device attributes array.
	 * @return A NSArray of device attributes or null if none present.
	 */
	NSArray getDeviceAttributes() {
    	NSObject c = nsdict.get("PayloadContent");
    	if (c != null) {
    		NSObject o = ((NSDictionary)c).get("DeviceAttributes");;
    		if (o != null)
    			return (NSArray)o.toJavaObject();
    	}
    	return null;
	}

	public IosEnrollPayload(String url, IosPayload parent) {
		initialize(url, null, parent);
	}

	public IosEnrollPayload(String url, String challenge) {
		initialize(url, challenge, null);
	}

	public IosEnrollPayload(String url, String challenge, IosPayload parent) {
		initialize(url, challenge, parent);
	}
	
	public IosEnrollPayload(NSDictionary d) {
		super(d);
	}
}
