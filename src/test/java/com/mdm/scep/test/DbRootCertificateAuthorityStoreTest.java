package com.mdm.scep.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Enumeration;

import static org.junit.Assert.*;

import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mdm.scep.DbRootCertificateAuthorityStore;
import com.mdm.scep.DbConnectionStore;
import com.mdm.utils.RSAKeyPair;
import com.mdm.utils.X509CertificateGenerator;
import com.mdm.utils.test.X509CertificateGeneratorTest;

public class DbRootCertificateAuthorityStoreTest {
	
	private static final Logger LOG = LoggerFactory.getLogger(X509CertificateGeneratorTest.class);
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

	@Test
	public void test() {
		long nextSerialNumber = 0;
				
		System.out.println("Starting DbRootCertificateAuthorityStore test");
		DbRootCertificateAuthorityStore DbStore = new DbRootCertificateAuthorityStore();
		System.out.println("Returned from DbRootCertificateAuthorityStore constructor");
		
		int x = 0;
		while (x++ < 10) {
			nextSerialNumber = DbStore.getNextSerialNumber();
			System.out.println("Next serial number returned was " + nextSerialNumber);
		}
	}
	
	@Test
	public void test2() {
		
		Connection c1 = null;
		Connection c2 = null;
		Connection c3 = null;
		Connection c4 = null;
	
	    String DbName = "mdm4all_db";
		String DbTableName = "CaCertNextSerialNumberTable";
		String DbColumnName = "CaCertNextSerialNumber";
		String sql; // sql statements to be executed
		Statement stmt = null;
		
		
		System.out.println("Starting DbRootStore test");
		
		DbConnectionStore dbcstest = DbConnectionStore.getInstance();
		
		// Try freeing a null connection
		dbcstest.freeConnection(c1);
		
		int x = 0;
		while ( x++ < 100) {
			// Get a connections serially and return them to the pool each time.
			// Confirm sql execution. Should be the same physical connection each time.
			// Test 1
			try {
			c1 = dbcstest.getConnection();
		      // Execute an insert statement which will cause the db to generate the next serial number.     		                  
		      stmt = c1.createStatement();	      
		      sql = "INSERT INTO " + DbName + "." + DbTableName + " (" + DbColumnName + ") VALUES (default);";
		      stmt.executeUpdate(sql);
			}catch(SQLException se){
			      //Handle errors for JDBC
			      se.printStackTrace();
			}
			dbcstest.freeConnection(c1);
		}
		
	

	    // Get and return connections to the pool
		c1 = dbcstest.getConnection();
		dbcstest.freeConnection(c1);
		
		c1 = dbcstest.getConnection();
		dbcstest.freeConnection(c1);
		
		c1 = dbcstest.getConnection();
		dbcstest.freeConnection(c1);
		
		c1 = dbcstest.getConnection();
		dbcstest.freeConnection(c1);
		
		System.out.println("Ending DbRootStore test"); // Check serial number table by hand to confirm values added.
	
	}
	
}
