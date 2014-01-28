/**
 * 
 */
package com.mdm.scep;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

import com.mdm.utils.X509CertificateGenerator;

import java.sql.*;

/**
 * @author dan
 *
 */
public class DbRootCertificateAuthorityStore implements
		IRootCertificateAuthorityStore {
	
	// TODO: remove map related variables and code when db procedures implemented.
    private static Map<IssuerAndSerialNumber, RootCertificateAuthority> CA_CACHE = null;
    private static Map<IssuerAndSerialNumber, RootCertificateAuthorityResult> ISSUED_CACHE = null;
    
    // Database related info. 
    private static String DbName = "mdm4all_db";
	private static String DbRootCaCertAuthTableName 			= "RootCertificateAuthorityTable";
	private static String DbRootCaCertAuthColRootCax509CertData = "RootCAx509CertData";
	private static String DbRootCaCertAuthColRax509CertData 	= "Rax509CertData";
	private static String DbRootCaCertAuthColRaPrivKey			= "RaPrivateKey";
	private static String DbRootCaCertAuthColCaRootIasn 		= "CaRootIssuerAndSerialNumber";
	private static String DbRootCaCertAuthColRaRootIasn			= "RaRootIssuerAndSerialNumber";


	
	/**
	 * Default constructor
	 */
	public DbRootCertificateAuthorityStore() {
		
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public RootCertificateAuthority createCA(X509Certificate caCert,
			IssuerAndSerialNumber caIasn, X509Certificate raCert,
			PrivateKey raKey, boolean enabledState, String objectId)
			throws RootCertificateAuthorityException {

		synchronized(DbRootCertificateAuthorityStore.class) {
			
			String sql; // sql statements to be executed
			Connection conn = null;
			PreparedStatement stmt = null;
			boolean dupEntry = false; // throw exception if entry already exists in database
		
			DbConnectionStore dbcs = DbConnectionStore.getInstance();	

		   try{
			   
		      //STEP 1: Get a database connection
		      conn = dbcs.getConnection();
		      
		      IssuerAndSerialNumber raIasn = X509CertificateGenerator.getIssuerAndSerialNumber((X509Certificate) raCert);
		      
		      
		      //STEP 2: Insert the data. If ca already exists, will throw exception    
		      // TODO: do we need to store the enabled state with the CA table? If so, need a new column.
	 
		      sql = "INSERT INTO " + DbName + "." + DbRootCaCertAuthTableName + " (" + 
		    		  DbRootCaCertAuthColRootCax509CertData + ", " +
		    		  DbRootCaCertAuthColRax509CertData + ", " +
		    		  DbRootCaCertAuthColRaPrivKey + ", " +
		    		  DbRootCaCertAuthColCaRootIasn + ", " +
		    		  DbRootCaCertAuthColRaRootIasn + " " +
		    		  ") VALUES (?, ?, ?, ?, ?);";
     
		      stmt = conn.prepareStatement(sql);
		            
		      stmt.setBytes(1, caCert.getEncoded());
		      stmt.setBytes(2, raCert.getEncoded());
		      stmt.setBytes(3, raKey.getEncoded());
		      stmt.setString(4, toDbInsertableString(caIasn));
		      stmt.setString(5, toDbInsertableString(raIasn));
	
		      stmt.executeUpdate();
		      stmt.close();
		 	      
		   }catch(SQLException se){
		      //Handle errors for JDBC
			   String str1, str2;
			   str1 = se.getMessage();
			   str2 = "Duplicate Entry";
			   
			   if (str1.toLowerCase().contains(str2.toLowerCase())) 
					   dupEntry = true;
					   
			   //System.out.println("sql exception:" + se.getMessage());
		       se.printStackTrace();
		       
		   }catch(Exception e){
		      //Handle other errors
		      e.printStackTrace();
		   }finally{
		      //finally block used to close resources
		      try{
		         if(stmt!=null)	 		        	 
		            stmt.close();
		        	      	
		      } catch (SQLException se2){
		    	  // nothing we can do 
		      }

		   }//end try
		   			
		   if (dupEntry) {
				System.out.println("Duplicate entry found");
				throw new RootCertificateAuthorityException("Duplicate RootCertificateAuthority");
		   }
		
		   RootCertificateAuthority ca = new RootCertificateAuthority();
		   ca.setConnector(new DbRootCertificateAuthorityConnector(this, caCert, raCert, raKey, enabledState));
		   return ca;
		   
		} // synchronize
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public void deleteCA(RootCertificateAuthority ca)
			throws RootCertificateAuthorityException {

		synchronized(DbRootCertificateAuthorityStore.class) {
			IssuerAndSerialNumber caIasn = X509CertificateGenerator.getIssuerAndSerialNumber(ca.getCaCertificate());
			RootCertificateAuthority entry = CA_CACHE.get(caIasn);
			if (entry == null)
				throw new RootCertificateAuthorityException("CA not in cache");
			
			for (IssuerAndSerialNumber iasn: entry.getIssuedList()) {
				ISSUED_CACHE.remove(iasn);
			}
			CA_CACHE.remove(caIasn);
		}
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public RootCertificateAuthority getCA(IssuerAndSerialNumber iasn) {

		synchronized(DbRootCertificateAuthorityStore.class) {
			RootCertificateAuthority ca = CA_CACHE.get(iasn);
			if (iasn.equals(X509CertificateGenerator.getIssuerAndSerialNumber(ca.getCaCertificate()))) {
				return ca;
			}
			// Must be the iasn for an issued certificate
			return null;
		}
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public RootCertificateAuthorityResult getIssued(IssuerAndSerialNumber iasn) {

		synchronized(DbRootCertificateAuthorityStore.class) {
			RootCertificateAuthorityResult result = ISSUED_CACHE.get(iasn);
			if (iasn.equals(X509CertificateGenerator.getIssuerAndSerialNumber(result.getCa().getCaCertificate()))) {
				// Must be the CA
				return null;
			}
			// Must be the iasn for an issued certificate
			return result;
		}
	}
	
    /**
     * {@inheritDoc}
     */
	@Override
	public long getNextSerialNumber() {
		   
		long theNextSerialNumber = 0;
		String DbTableName = "CaCertNextSerialNumberTable";
		String DbColumnName = "CaCertNextSerialNumber";
		String sql; // sql statements to be executed
		ResultSet rs = null;
		
		Connection conn = null;
		Statement stmt = null;
		
		DbConnectionStore dbcs = DbConnectionStore.getInstance();
		
	   try{
		   
	      //STEP 1: Get a database connection
	      conn = dbcs.getConnection();
      
	      //STEP 2: We want the creation of the next serial number and the "cleanup" of the table
	      // (removal of old id's) to be synchronized from other threads to ensure two threads
	      // don't attempt to create a new id and access/delete at the same time.
	      synchronized(DbRootCertificateAuthorityStore.class) {
	           
		      //STEP 3: Execute an insert statement which will cause the db to generate the next serial number.     		                  
		      stmt = conn.createStatement();	      
		      sql = "INSERT INTO " + DbName + "." + DbTableName + " (" + DbColumnName + ") VALUES (default);";
		      stmt.executeUpdate(sql);
		      stmt.close();
	      
		      // Get the next serial number just created in the database
		      stmt = conn.createStatement();
		      rs = stmt.executeQuery("SELECT LAST_INSERT_ID()");
	      
		      if (rs.next()) {
		          theNextSerialNumber = rs.getInt(1);
		      }
	      
			  // Do some cleanup: only keep the last serial number, delete others from the table.
			  sql = "DELETE FROM " + DbName + "." + DbTableName + " WHERE " + DbTableName + "." + DbColumnName + " <> " + theNextSerialNumber;
			  stmt.executeUpdate(sql);
	  
		      rs.close();
		      stmt.close();
	      } /* synch */
	      
	   }catch(SQLException se){
	      //Handle errors for JDBC
	      se.printStackTrace();
	   }catch(Exception e){
	      //Handle other errors
	      e.printStackTrace();
	   }finally{
	      //finally block used to close resources
	      try{
	         if(stmt!=null)	 		        	 
	            stmt.close();
	         
		      	if (rs!=null)
		      		rs.close();
		      	
	      } catch (SQLException se2){
	    	  // nothing we can do 
	      }

	   }//end try
	   
	   // db connection must be returned to pool
	   dbcs.freeConnection(conn);
		   
	   return theNextSerialNumber;
	}
	
	// Extract Issue and Serial number fields and create a string to be inserted into the database.
	// This field uniquely identifies a certificate for us.
	private String toDbInsertableString(IssuerAndSerialNumber caIasn) {
        
		X500Name certname = caIasn.getName();
        ASN1Integer sn = caIasn.getSerialNumber();
        return ( sn.toString() + certname.toString() );
		
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public RootCertificateAuthority getCA(String objectId) {
		// TODO Get the CA certificate from its object id
		return null;
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public RootCertificateAuthorityResult getIssued(String objectId) {
		// TODO Get the issued certificate from its object id
		return null;
	}
	
}
