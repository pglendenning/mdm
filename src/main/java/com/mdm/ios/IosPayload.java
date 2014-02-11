package com.mdm.ios;

import com.dd.plist.*;
import com.mdm.utils.MdmServiceProperties;

import java.util.Date;
import java.util.InvalidPropertiesFormatException;
import java.util.UUID;
import java.io.IOException;
import java.lang.String;

public class IosPayload  {
    
	protected NSDictionary nsdict;
	
	/**
     * Content common to all payloads.
     * Includes PayloadVersion, PayloadUUID, and PayloadOrganization.
     */
    protected void init1() {
    	nsdict.put("PayloadVersion", 1);
    	nsdict.put("PayloadUUID", UUID.randomUUID().toString());
    	nsdict.put("PayloadOrganization", MdmServiceProperties.getProperty("CompanyLegalName"));
    }
    
	/**
	 * Safe setting of a key value. Ignores null or empty values.
	 */
	public void safeSetKey(String key, String val) {
		if (val != null && !val.isEmpty())
			nsdict.put(key, val);
	}
	
	/**
	 * Safe setting of a key value. Ignores null values.
	 */
	public void safeSetKey(String key, Boolean val) {
		if (val != null)
			nsdict.put(key, (boolean)val);
	}
	
	/**
	 * Safe setting of a key value. Ignores null values.
	 */
	public void safeSetKey(String key, Date val) {
		if (val != null)
			nsdict.put(key, val);
	}
	
    /**
     * Get the payload version.
     */
    public long getVersion() {
    	NSObject o = nsdict.get("PayloadVersion");
    	if (o != null)
    		return (Long)o.toJavaObject();
    	return 0;
    }
    
    /**
     * Get the payload uuid as a string.
     */
    public String getUUID() {
    	NSObject o = nsdict.get("PayloadUUID");
    	if (o != null)
    		return (String)o.toJavaObject();
    	return "";
    }
    
    /**
     * Get the payload organization.
     */
    public String getOrganization() {
    	NSObject o = nsdict.get("PayloadOrganization");
    	if (o != null)
    		return (String)o.toJavaObject();
    	return "";
    }

    /**
     * Get the payload identifier.
     */
    public String getIdentifier() {
    	NSObject o = nsdict.get("PayloadIdentifier");
    	if (o != null)
    		return (String)o.toJavaObject();
    	return "";
    }
    
    /**
     * Get the payload type.
     */
    public String getPayloadType() {
    	NSObject o = nsdict.get("PayloadType");
    	if (o != null)
    		return (String)o.toJavaObject();
    	return "";
    }
    
    /**
     * Get the payload display name.
     */
    public String getDisplayName() {
    	NSObject o = nsdict.get("PayloadDisplayName");
    	if (o != null)
    		return (String)o.toJavaObject();
    	return "";
    }
    
    /**
     * Get the payload description.
     */
    public String getDescription() {
    	NSObject o = nsdict.get("PayloadDescription");
    	if (o != null)
    		return (String)o.toJavaObject();
    	return "";
    }

    /**
     * Convert to an XML Plist
     * @return	An XML PList.
     */
	public String toXMLPropertyList() {
		return nsdict.toXMLPropertyList();
	}
	
    /**
     * Return the payload for the given NSDictionary.
     * @param d	A NSDictionary to decode
     */
	public final static IosPayload toIosPayload(NSDictionary d) {
		IosPayload p = new IosPayload(d);
		String type = p.getPayloadType();
		if (type == "com.apple.applicationaccess")
			return new IosRestrictionsPayload(d);
		else if (type == "com.apple.webClip.managed")
			return new IosWebClipPayload(d);
		return null;
	}

    /**
	 * Construct a base payload.
	 */
	public IosPayload() {
		nsdict = new NSDictionary();
		/* Must be done in unit test
		try {
			MdmServiceProperties.Initialize();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/
	}
	
	/**
	 * Construct an IosPayload from a dictionary.
	 * @param d
	 */
	public IosPayload(NSDictionary d) {
		nsdict = d;
	}	
}
