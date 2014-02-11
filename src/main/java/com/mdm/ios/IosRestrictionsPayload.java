package com.mdm.ios;

import com.dd.plist.*;
import com.mdm.utils.MdmServiceProperties;

import java.util.HashMap;
import java.util.Map;


/**
 * A Restrictions payload allows the administrator to restrict the user
 * from doing certain things with the device, such as using the camera.
 * Not supported in OS X.
 */
public final class IosRestrictionsPayload extends IosPayload {
	    
    /**
     * Optional. When false, the App Store is disabled and its icon is
     * removed from the Home screen. Users are unable to install or update
     * their applications.
     */
    public final static int ALLOW_APP_INSTALL = 0x1;
    
    /**
     * Optional. When false, disables Siri. Defaults to true.
     */
    public final static int ALLOW_SIRI = 0x2;
    
	/**
	 * Optional. When false, the user is unable to use Siri when the device
	 * is locked. Defaults to true. This restriction is ignored if the device
	 * does not have a passcode set.
	 */
    public final static int ALLOW_SIRI_WHILE_LOCKED = 0x4;

	/**
	 * Optional. When false, the camera is completely disabled and its icon
	 * is removed from the Home screen. Users are unable to take photographs.
	 */
    public final static int ALLOW_CAMERA = 0x8;
    
    /**
     * Optional. When false, this prevents the device from automatically
     * submitting diagnostic reports to Apple. Defaults to true.
     */
    public final static int ALLOW_DIAGNOSTICS = 0x10;
    
    /**
     * Optional. When false, explicit music or video content purchased from
     * the iTunes Store is hidden. Explicit content is marked as such by
     * content providers, such as record labels, when sold through the iTunes 
     * Store.
     */
    public final static int ALLOW_ADULT_CONTENT = 0x20;
    
    /**
     * Optional. If set to false, the user will not be able to download
     * media from the iBookstore that has been tagged as erotica. This will
     * default to true. Supervised only.
     */
    public final static int ALLOW_ADULT_BOOKS = 0x40;
    
    /**
     * Optional. When false, users are unable to save a screenshot of the
     * display.
     */
    public final static int ALLOW_SCREEN_SHOT = 0x80;
    
    /**
     * Optional. When false, the YouTube application is disabled and its
     * icon is removed from the Home screen.
     * Ignored in iOS 6 and later because the YouTube app is not provided.
     */
    public final static int ALLOW_YOUTUBE = 0x100;
    
    /**
     * Optional. When false, the iTunes Music Store is disabled and its
     * icon is removed from the Home screen. Users cannot preview, purchase,
     * or download content.
     */
    public final static int ALLOW_ITUNES = 0x200;
    
    /**
     * Optional. When true, forces user to enter their iTunes password
     * for each transaction.
     */
    public final static int FORCE_ITUNES_PASSWD = 0x400;
    
    /**
     * Optional. When false, the Safari web browser application is disabled
     * and its icon removed from the Home screen. This also prevents users
     * from opening web clips.
     */
    public final static int ALLOW_SAFARI = 0x800;
    
    /**
     * Optional. When false, automatically rejects untrusted HTTPS
     * certificates without prompting the user.
     */
    public final static int ALLOW_UNTRUSTED_TLS_PROMPT = 0x1000;
    
    /**
     * Optional. When false, disables backing up the device to iCloud.
     */
    public final static int ALLOW_CLOUD_BACKUP = 0x2000;
    
    /**
     * Optional. When false, disables document and key-value syncing to
     * iCloud.
     */
    public final static int ALLOW_CLOUD_SYNC = 0x4000;
    
    /**
     * Optional. When false, disables Photo Stream.
     */
    public final static int ALLOW_PHOTO_STREAM = 0x8000;
    
    /**
     * Optional. If set to false, iBookstore will be disabled. This will
     * default to true. Supervised only.
     */
    public final static int ALLOW_BOOKS = 0x10000;
    
    /**
     * Optional. If set to false, Passbook notifications will not be shown
     * on the lock screen.This will default to true.
     */
    public final static int ALLOW_PASSBOOK_WHILE_LOCKED = 0x20000;
    
    /**
     * Optional. If set to false, Shared Photo Stream will be disabled. 
     * This will default to true.
     */
    public final static int ALLOW_SHARED_STREAM = 0x40000;
    
    /**
     * Optional. If set to false, the user is prohibited from installing
     * configuration profiles and certificates interactively.
     * This will default to true. Supervised only.
     */
    public final static int ALLOW_CONFIG_PROFILE_INSTALL = 0x80000;
    
    /**
     * Optional. If set to false, Game center will be disabled. 
     * This will default to true.
     */
    public final static int ALLOW_GAME_CENTER = 0x100000;
    
    private final static HashMap<String, Integer> nameToFlag = initializeMap();
    
    private final static HashMap<String, Integer> initializeMap() {
    	HashMap<String, Integer> m = new HashMap<String, Integer>();
    	m.put("allowAppInstallation", ALLOW_APP_INSTALL);
    	m.put("allowAssistant", ALLOW_SIRI);
    	m.put("allowAssistantWhileLocked", ALLOW_SIRI_WHILE_LOCKED);
    	m.put("allowCamera", ALLOW_CAMERA);
    	m.put("allowDiagnosticSubmission", ALLOW_DIAGNOSTICS);
    	m.put("allowExplicitContent", ALLOW_ADULT_CONTENT);
    	m.put("allowGameCenter", ALLOW_GAME_CENTER);
    	m.put("allowScreenShot", ALLOW_SCREEN_SHOT);
    	m.put("allowYouTube", ALLOW_YOUTUBE);
    	m.put("allowiTunes", ALLOW_ITUNES);
    	m.put("forceITunesStorePasswordEntry", FORCE_ITUNES_PASSWD);
    	m.put("allowSafari", ALLOW_SAFARI);
    	m.put("allowUntrustedTLSPrompt", ALLOW_UNTRUSTED_TLS_PROMPT);
    	m.put("allowCloudBackup", ALLOW_CLOUD_BACKUP);
    	m.put("allowCloudDocumentSync", ALLOW_CLOUD_SYNC);
    	m.put("allowPhotoStream", ALLOW_PHOTO_STREAM);
    	m.put("allowBookstore", ALLOW_BOOKS);
    	m.put("allowBookstoreErotica", ALLOW_ADULT_BOOKS);
    	m.put("allowPassbookWhileLocked", ALLOW_PASSBOOK_WHILE_LOCKED);
    	m.put("allowSharedStream", ALLOW_SHARED_STREAM);
    	m.put("allowUIConfigurationProfileInstallation", ALLOW_CONFIG_PROFILE_INSTALL);
    	return m;
    }
    
    private void initialize(int flagsOn, int flagsOff, IosPayload parent) {
    	int settings = flagsOn|flagsOff;
    	init1();
    	if (parent != null)
    		nsdict.put("PayloadIdentifier", MdmServiceProperties.getProperty("RestrictionsServiceName")+parent.getUUID());
    	else
    		nsdict.put("PayloadIdentifier", MdmServiceProperties.getProperty("RestrictionsServiceName"));
		nsdict.put("PayloadType", "com.apple.applicationaccess");
		nsdict.put("PayloadDescription", "Configures device restrictions.");
		nsdict.put("PayloadDisplayName", "Restrictions");
		for (Map.Entry<String, Integer> entry : nameToFlag.entrySet()) {
		    String key = entry.getKey();
		    Integer mask = entry.getValue();
			if (0 != (settings & mask))
			    nsdict.put(key, 0 != (flagsOn & mask));
		}
    }
    
    /**
     * Get the configurations settings as a bit mask.
     * @return	The configuration settings.
     */
    public int getSettings() {
    	int settings = 0;
		for (Map.Entry<String, NSObject> entry : nsdict.entrySet()) {
		    String key = entry.getKey();
		    NSObject o = entry.getValue();
	    	Integer mask = nameToFlag.get(key);
	    	if (mask != null && (Boolean)o.toJavaObject()) {
		    	settings |= mask;
	    	}
		}
		return settings;
    }
    
    /**
     * Construct a payload instance.
     * @param flagsOn	Integer bit mask representing the restrictions to enable.
     * @param flagsOff	Integer bit mask representing the restrictions to disable.
     * @param parent	The parent container.
     */
    public IosRestrictionsPayload(int flagsOn, int flagsOff, IosPayload parent) {
    	initialize(flagsOn, flagsOff, parent);
    }
    
    /**
     * Construct a payload instance.
     * @param flagsOn	Integer bit mask representing the restrictions to enable.
     * @param flagsOff	Integer bit mask representing the restrictions to disable.
     */
    public IosRestrictionsPayload(int flagsOn, int flagsOff) {
    	initialize(flagsOn, flagsOff, null);
    }
    
    /**
     * Construct a payload instance..
     * @param d	A NSDictionary to decode
     */
    public IosRestrictionsPayload(NSDictionary d) {
    	super(d);
    }  
}
