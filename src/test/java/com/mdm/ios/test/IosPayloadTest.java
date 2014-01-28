package com.mdm.ios.test;

import com.dd.plist.*;
import com.mdm.ios.*;
import com.mdm.utils.MdmServiceProperties;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class IosPayloadTest {
	@Before
	public void setUp() {
		try {
			MdmServiceProperties.Initialize();
		} catch (Exception e) {
			fail("MdmServiceProperties.initialize() error");
		}
	}
	
	@Test
	public void testRestrictions() {
		int cfg = IosRestrictionsPayload.ALLOW_APP_INSTALL|
				IosRestrictionsPayload.ALLOW_CAMERA|
				IosRestrictionsPayload.ALLOW_CONFIG_PROFILE_INSTALL|
				IosRestrictionsPayload.ALLOW_DIAGNOSTICS|
				IosRestrictionsPayload.ALLOW_GAME_CENTER|
				IosRestrictionsPayload.ALLOW_SCREEN_SHOT|
				IosRestrictionsPayload.FORCE_ITUNES_PASSWD;
		IosRestrictionsPayload p1 = new IosRestrictionsPayload(cfg, 0);
		IosRestrictionsPayload p2 = null;
		try {
			PrintStream f = new PrintStream("IosPayloadTest.plist");
			f.print(p1.toXMLPropertyList());
			f.close();
		} catch (FileNotFoundException e) {
			fail("Cannot open IosPayloadTest.plist for write");
		}
		
		try {
			NSDictionary d =  (NSDictionary)PropertyListParser.parse(new File("IosPayloadTest.plist"));
			p2 = new IosRestrictionsPayload(d);
		} catch (FileNotFoundException e) {
			fail("Cannot open IosPayloadTest.plist for read");
		} catch (Exception e) {
			fail("Not an NSDictionary");
		}
		
		int settings = p2.getSettings();
		assertTrue(settings == cfg);
	}

}
