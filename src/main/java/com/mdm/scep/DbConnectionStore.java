
package com.mdm.scep;

import java.io.FileReader;
import java.util.Vector;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.commons.io.IOUtils;


public class DbConnectionStore{
 
    // Private constructor for singleton class
    private static DbConnectionStore instance = null;
    
    // Database related info. 
    // TODO: Should not use root account with no password, but need to use root in creating database.
    // TODO: Maybe in a config file?
    private static String DriverName = "com.mysql.jdbc.Driver";
    //private static String DbName = "mdm4all_db";
    
    // FIXME: 2014-Jan-11/PWG
    // DAN, the scheme file should be located in src/main/resources for deployment
    // or src/test/resources for test. Maven will copy the schema to the WAR folder
    // on deployment. Also don't hardcode any constants that we may need change at 
    // runtime. If you hard code we have to rebuild for trivial changes = not ok.
    //
    // Use the com.mdm.utils.MdmServiceProperties to access property strings. From
    // your perspective you can assume init has been called - make sure you do this
    // in test cases.
    private static String DbUrl = "jdbc:mysql://localhost/";
    private static String DbUser = "root";
    private static String DbPass = "";
    private static String DbSchemaFileName = "mdm4all_db_schema_ddl.sql";
    
    // Store pool of free database connections. If no connection available upon request,
    // create one and return it. For now, not tracking used connections. Might choose to
    // do so later at some point if cleanup is needed for any reason.
    private static Vector<Connection> freeConnections = new Vector<Connection>();

    // Empty constructor
    private DbConnectionStore(){
    	
    }
    
    // Singleton GetInstance
    public static synchronized DbConnectionStore getInstance(){
        if (instance==null) {
        	instance = new DbConnectionStore();
        	instance.InitializeDb();
        }
             
        return instance;
    }
    
    
    // Create database using defined ddl file.
    // If database exists already, leave it.
    private void InitializeDb(){
    	
		Connection conn = null;
		Statement stmt = null;
    	
		try{	
						   
		   //STEP 1: Register JDBC driver
		   Class.forName(DriverName).newInstance();

		   // "allowMultiQueries allows multiple queries in the file with the semicolon as a delimeter
		   conn = DriverManager.getConnection(DbUrl + "?allowMultiQueries=true", DbUser, DbPass);
		   	   
		   //STEP 2: Execute the ddl from the db schema file to create the database. If the database exists
		   // already, nothing will be done.
		   
		   // FIXME: 2014-Jan-11/PWG
		   // Lets change this to use com.mdm.utils.MdmServiceProperties.
		   String homeDir = System.getProperty("user.home");	   
		   String query = IOUtils.toString(new FileReader(homeDir + "/" + DbSchemaFileName));
		   //System.out.println("About to create ddl");  
		   stmt = conn.prepareStatement(query);
		   //System.out.println("Created ddl");
		   
		   stmt.execute(query);
		   stmt.close();

		   conn.close();
	      		      
		}catch(SQLException se){
		   //Handle errors for JDBC
		   se.printStackTrace();
		}catch(Exception e){
		   //Handle errors for Class.forName
		   e.printStackTrace();
		}finally{
		   //finally block used to close resources
		   try{
		      if(stmt!=null)
		         stmt.close();
		   }catch(SQLException se2){
		   }// nothing we can do
		   try{
		      if(conn!=null)
		         conn.close();
		   }catch(SQLException se){
		      se.printStackTrace();
		   }//end finally try
		}//end try
    }

    
    // Get a connection from the pool
    public synchronized Connection getConnection(){
    	
		Connection connection = null;

		if (freeConnections.size() > 0) {
			connection = (Connection) freeConnections.elementAt(0);
			freeConnections.removeElementAt(0);

			try {

				if (connection.isClosed()) {
					connection = getConnection();
				}
			} catch (Exception e) {

				e.printStackTrace();
				connection = getConnection();
			}

			return connection;
			
		} else {
			
			// No free connections. Attempt to create a new one
			connection = newConnection();
		}

		return connection;
    }
    	   
    
    // Return a connection to the pool
    public void freeConnection(Connection conn){
    	
    	if (conn != null) 
    	if (!freeConnections.contains(conn)) 
    		freeConnections.addElement(conn);
    }
    
    // Get a new connection
	private Connection newConnection() {

		Connection conn = null;

		try {

			conn = DriverManager.getConnection(DbUrl, DbUser, DbPass);

		} catch (Exception e) {

			e.printStackTrace();
			return null;
		}
    	
		return conn;
	}
}
