package com.mdm.ios;

import com.dd.plist.*;
import com.mdm.utils.MdmServiceProperties;

public class IosScepPayload extends IosPayload {
	
	private NSArray createNSArray(String s1, String s2) {
		NSArray a = new NSArray(2);
		a.setValue(0, new NSString(s1));
		a.setValue(1, new NSString(s2));
		return a;
	}
	
	private void initialize(String url, String challenge, IosPayload parent) {
		// Create a profile service payload
		init1();
    	if (parent != null)
    		nsdict.put("PayloadIdentifier", MdmServiceProperties.getProperty("ScepServiceName")+parent.getUUID());
    	else
    		nsdict.put("PayloadIdentifier", MdmServiceProperties.getProperty("ScepServiceName"));
		nsdict.put("PayloadType", "com.apple.security.scep"); // do not modify
		// strings that show up in UI, customizable
		nsdict.put("PayloadDisplayName", MdmServiceProperties.getProperty("CompanyShortName") + " Scep Service");
		nsdict.put("PayloadDescription", "Provides device encryption identity");
		
		NSDictionary content = new NSDictionary();
		
		content.put("URL", url);
		// NOTE: name required for MS SCEP servers.
		content.put("Name", MdmServiceProperties.getProperty("ScepContentName"));
		
		NSArray a1 = new NSArray(1);
		NSArray a2 = new NSArray(1);
		NSArray a3 = new NSArray(2);
		a1.setValue(0, createNSArray("O", MdmServiceProperties.getProperty("CompanyLegalName")));
		a2.setValue(0, createNSArray("CN", MdmServiceProperties.getProperty("ScepCN")));
		a3.setValue(0, a1);
		a3.setValue(1, a2);
		content.put("Subject", a3);
		
		content.put("Keysize", 1024);
		content.put("Key Type", "RSA");
		content.put("Key Usage", 5);	// digital signature (1) | key encipherment (4)
        // SCEP can run over HTTP, as long as the CA cert is verified out of band
        // Below we achieve this by adding the fingerprint to the SCEP payload
        // that the phone downloads over HTTPS during enrollment
        // Disabled until the following is fixed: <rdar://problem/7172187> SCEP various fixes
        // content.put("CAFingerprint", StringIO.(OpenSSL.Digest.SHA1(root_cert.to_der).digest))
		if (challenge != null && !challenge.isEmpty())
			content.put("Challenge", challenge);
		nsdict.put("PayloadContent", content);
	}
	
	public IosScepPayload(String url, IosPayload parent) {
		initialize(url, null, parent);
	}

	public IosScepPayload(String url) {
		initialize(url, null, null);
	}

	public IosScepPayload(String url, String challenge) {
		initialize(url, challenge, null);
	}

	public IosScepPayload(String url, String challenge, IosPayload parent) {
		initialize(url, challenge, parent);
	}
	
	public IosScepPayload(NSDictionary d) {
		super(d);
	}
}
