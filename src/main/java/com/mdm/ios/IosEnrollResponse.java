package com.mdm.ios;

import com.dd.plist.NSDictionary;
import com.dd.plist.NSObject;

public final class IosEnrollResponse {
	
	private NSDictionary nsdict;
    
    /**
     * Get the device version.
     */
    public long getVersion() {
    	NSObject o = nsdict.get("VERSION");
    	if (o != null)
    		return (Long)o.toJavaObject();
    	return 0;
    }
    
    /**
     * Get the device UDID as a string.
     */
    public String getUDID() {
    	NSObject o = nsdict.get("UDID");
    	if (o != null)
    		return (String)o.toJavaObject();
    	return null;
    }
    
    /**
     * Get the device MAC address.
     */
    public String getMacAddressEN0() {
    	NSObject o = nsdict.get("MAC_ADDRESS_EN0");
    	if (o != null)
    		return (String)o.toJavaObject();
    	return null;
    }

    /**
     * Get the challenge.
     */
    public String getChallenge() {
    	NSObject o = nsdict.get("CHALLENGE");
    	if (o != null)
    		return (String)o.toJavaObject();
    	return null;
    }
    
    /**
     * Get the device serial number.
     */
    public String getPayloadType() {
    	NSObject o = nsdict.get("SERIAL");
    	if (o != null)
    		return (String)o.toJavaObject();
    	return null;
    }

    /**
	 * Construct an IosPayload from a dictionary.
	 * @param d
	 */
	public IosEnrollResponse(NSDictionary d) {
		nsdict = d;
	}

}
