package com.mdm.ios;

import java.util.UUID;

import com.dd.plist.NSDictionary;
import com.dd.plist.NSObject;
import com.mdm.utils.MdmServiceProperties;


/**
 * The web clip payload installs a URL shortcut on and iOS home screen.
 * Custom icon not supported currently.
 * @author paul
 */
public final class IosWebClipPayload extends IosPayload {

	private void initialize(String url, boolean removable, String label, /*String icon, */UUID uuid) {
		init1();
    	if (uuid != null)
    		nsdict.put("PayloadIdentifier", MdmServiceProperties.getProperty("WebClipServiceName")+uuid.toString());
    	else
    		nsdict.put("PayloadIdentifier", MdmServiceProperties.getProperty("WebClipServiceName"));
        nsdict.put("PayloadType", "com.apple.webClip.managed"); // do not modify
        // strings that show up in UI, customizable
        nsdict.put("PayloadDescription", "Creates a link to the " + 
        		MdmServiceProperties.getProperty("CompanyLegalName") + " home page");
        nsdict.put("PayloadDisplayName", MdmServiceProperties.getProperty("CompanyLegalName"));
        nsdict.put("IsRemovable", removable);
        if (label != null && !label.isEmpty())
            nsdict.put("Label", label);
        else
            nsdict.put("label", MdmServiceProperties.getProperty("CompanyLegalName"));
        nsdict.put("URL", url);
	}
	
    /**
     * Get the webclip removable flag.
     */
	public boolean isRemovable() {
    	NSObject o = nsdict.get("IsRemovable");
    	if (o != null)
    		return (Boolean)o.toJavaObject();
    	return false;
	}
	
    /**
     * Get the webclip label.
     */
	public String getLabel() {
    	NSObject o = nsdict.get("Label");
    	if (o != null)
    		return (String)o.toJavaObject();
    	return "";
	}
	
    /**
     * Get the webclip URL.
     */
	public String getURL() {
    	NSObject o = nsdict.get("URL");
    	if (o != null)
    		return (String)o.toJavaObject();
    	return "";
	}
	
	/**
	 * Construct a web-clip payload instance.
	 * @param url		URL shortcut to place on users home screen
	 * @param removable	If True the shortcut can be removed by the user.
	 */
	public IosWebClipPayload(String url, boolean removable) {
		initialize(url, removable, null, null);
	}

	/**
	 * Construct a web-clip payload instance.
	 * @param url		URL shortcut to place on users home screen
	 * @param removable	If True the shortcut can be removed by the user.
	 * @param label		A label to apply to the shortcut
	 */
	public IosWebClipPayload(String url, boolean removable, String label) {
		initialize(url, removable, label, null);
	}

	/**
	 * Construct a web-clip payload instance.
	 * @param url		URL shortcut to place on users home screen
	 * @param removable	If True the shortcut can be removed by the user.
     * @param uuid		Configuration profile UUID.
	 */
	public IosWebClipPayload(String url, boolean removable, UUID uuid) {
		initialize(url, removable, null, uuid);
	}
	
	/**
	 * Construct a web-clip payload instance.
	 * @param url		URL shortcut to place on users home screen
	 * @param removable	If True the shortcut can be removed by the user.
	 * @param label		A label to apply to the shortcut
     * @param uuid		Configuration profile UUID.
	 */
	public IosWebClipPayload(String url, boolean removable, String label, UUID uuid) {
		initialize(url, removable, label, uuid);
	}

    /**
     * Construct a payload instance..
     * @param d	A NSDictionary to decode
     */
    public IosWebClipPayload(NSDictionary d) {
    	super(d);
    }
}
