package com.mdm.ios;

/**
 * MDM Access Rights - immutable class properties.
 */
public class IosRights {
	    
	/**Allow inspection of configuration profile.*/
	public final static int VIEW_CFG_PROFILE = 0x1;
	
	/** Allow installation and removal of configuration profiles.*/
	public final static int INSTALL_CFG_PROFILE = 0x1|0x1;
	
    /** Allow device lock and pass-code removal.*/
	public final static int DEVICE_LOCK = 0x4;
	
    /** Alloc device erase.*/
	public final static int DEVICE_ERASE = 0x8;
	
    /** 
     * Allow query of device information.
     * Information includes device capacity, serial number.
     */
	public final static int QUERY_DEVICE_INFO = 0x10;
	
    /**
     * Allow query of network information.
     * Information includes phone/SIM numbers, MAC address.
     */
	public final static int QUERY_NET_INFO = 0x20;
	
    /** Allow inspection of provisioning profiles.*/
	public final static int VIEW_PROV_PROFILE = 0x40;
	
    /** Allow installation and removal of provisioning profiles.*/
	public final static int INSTALL_PROV_PROFILE = 0x80|0x4;
	
    /** Allow inspection of installed apps.*/
	public final static int VIEW_INSTALLED_APPS = 0x100;
	
    /** Allow restriction related queries.*/
	public final static int QUERY_RESTRICTION = 0x200;
	
    /** Allow security related queries.*/
	public final static int QUERY_SECURITY = 0x400;
	
    /** Allow manipulations of settings.*/
	public final static int MODIFY_SETTINGS = 0x800;
	
    /** Allow App management.*/
	public final static int APP_MGMT = 0x1000;
	
    /** Default access rights.*/
	public final static int DEFAULT_RIGHTS = 0x1ffff;
}
