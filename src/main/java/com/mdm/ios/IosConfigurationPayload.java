/**
 * 
 */
package com.mdm.ios;

import java.util.Date;

import com.dd.plist.NSDictionary;
import com.mdm.utils.MdmServiceProperties;

/**
 * @author paul
 *
 */
public class IosConfigurationPayload extends IosPayload {
	
	public void setConsentText(String txt) {
		safeSetKey("ConsentText", txt);
	}
	
	public void setRemovalDate(Date date) {
		safeSetKey("ConsentText", date);
	}
	
	public void setEncrypted(boolean isEncrypted) {
		nsdict.put("IsEncrypted", isEncrypted);
	}
	
	public void setDisplayName(String name) {
		safeSetKey("PayloadDisplayName", name);		
	}
	
	public void setDescription(String dsecription) {
		safeSetKey("PayloadDescription", dsecription);				
	}
	
	public void setRemovalPassword(boolean requirePasswd) {
		nsdict.put("HasRemovalPasscode", requirePasswd);
	}
	
	public void setContent(IosPayload content) {
		nsdict.put("PayloadContent", content);
	}

	/**
	 * 
	 */
	public IosConfigurationPayload() {
		init1();
		nsdict.put("PayloadIdentifier", MdmServiceProperties.getProperty("ConfigProfileServiceName"));
		nsdict.put("PayloadType", "Configuration");
	}

	/**
	 * @param d
	 */
	public IosConfigurationPayload(NSDictionary d) {
		super(d);
	}

}
