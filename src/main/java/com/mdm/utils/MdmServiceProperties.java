package com.mdm.utils;

import java.util.*;
import java.io.*;
import java.lang.reflect.InvocationTargetException;

import javax.servlet.ServletContext;

/**
 * Properties used by the MDM service. These can be modified at runtime
 * without requiring a rebuild.
 * @author Paul Glendenning
 */
public final class MdmServiceProperties {
	
	/**
	 * The singular instance of this class
	 */
	private static Properties instance = null;
	
	/**
	 * Private construction to ensure we cannot create with new
	 */
	private MdmServiceProperties() {
	}
	
	/**
	 * Check if the instance is initialized. 
	 * @return The initialized state.
	 */
	public static boolean isInitialized() {
		return instance != null;
	}
	
	/**
	 * Runtime version of property initialization. Must be called by Servlets
	 * before any calls to MdmServiceProperties.get(). Servlets should override 
	 * init() as shown below:
	 * <pre>
	 * {@code
	 *	@Override
	 * 	public void init(ServletConfig config) throws ServletException {
	 * 		super.init(config);
	 * 		try {
	 * 			MdmServiceProperties.Initialize(config.getServletContext());
	 * 			return;
	 *		} catch (Exception e) {
	 * 			LOG.error("Cannot initialize MdmServiceProperties");
	 * 		}
	 * 		throw new ServletException();
	 *	}
	 * }
	 * </pre>
	 * <p>The runtme properties can be found at src/main/resources/mdmservice.xml.
	 * Maven will copy this file to WEB-INF/classes on deployment.</p>
	 * @param context	The servlet context.
	 * @throws InvalidPropertiesFormatException
	 * @throws IOException
	 */
	public static synchronized void Initialize(ServletContext context) throws InvalidPropertiesFormatException, IOException {
		if (instance == null)
		{
			InputStream is = context.getResourceAsStream("mdmservice.xml");
			instance = new Properties();
			instance.loadFromXML(is);
		}
	}
	
	/**
	 * Test version of property initialization. Must be called by unit tests
	 * before any calls to MdmServiceProperties.get(). Unit tests should 
	 * initialize as shown below:
	 * <pre>
	 * {@code
	 *	@Before
	 * 	public void setUp() {
	 * 		try {
	 * 			MdmServiceProperties.Initialize();
	 *		} catch (Exception e) {
	 * 			fail("MdmServiceProperties.initialize() error");
	 * 		}
	 *	}
	 * }
	 * </pre>
	 * <p>The test properties can be found at src/test/resources/mdmservice.xml.</p>
	 * @throws InvalidPropertiesFormatException
	 * @throws IOException
	 */
	public static synchronized void Initialize() throws InvalidPropertiesFormatException, IOException {
		if (instance == null)
		{
			InputStream is = MdmServiceProperties.class.getClassLoader().getResourceAsStream("mdmservice.xml");
			instance = new Properties();
			instance.loadFromXML(is);
		}
	}
	
	/**
	 * Construct a class, using the classes default constructor, given a property
	 * where the class name is stored.
	 * @return	A class instance.
	 * @throws ClassNotFoundException 
	 * @throws SecurityException 
	 * @throws NoSuchMethodException 
	 * @throws InvocationTargetException 
	 * @throws IllegalArgumentException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 */
	public static Object constructObject(String key) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException, ClassNotFoundException {
		String className = instance.getProperty(key);
		if (className == null)
			throw new ClassNotFoundException();
		return Class.forName(className).getConstructor().newInstance();
	}
	
	/**
	 * Construct a class, using the classes constructor, given a property
	 * where the class name is stored.
	 * @param	param	A parameter to the constructor.
	 * @return	A class instance.
	 * @throws ClassNotFoundException 
	 * @throws SecurityException 
	 * @throws NoSuchMethodException 
	 * @throws InvocationTargetException 
	 * @throws IllegalArgumentException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 */
	public static <T> Object constructObject(String key, T param) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException, ClassNotFoundException {
		String className = instance.getProperty(key);
		if (className == null)
			throw new ClassNotFoundException();
		return Class.forName(className).getConstructor(param.getClass()).newInstance(param);
	}
	
	/**
	 * Construct a class, using the classes constructor, given a property
	 * where the class name is stored.
	 * @param	param1	The first parameter to the constructor.
	 * @param	param2	The second parameter to the constructor.
	 * @return	A class instance.
	 * @throws ClassNotFoundException 
	 * @throws SecurityException 
	 * @throws NoSuchMethodException 
	 * @throws InvocationTargetException 
	 * @throws IllegalArgumentException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 */
	public static <T, U> Object constructObject(String key, T param1, U param2) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException, ClassNotFoundException {
		String className = instance.getProperty(key);
		if (className == null)
			throw new ClassNotFoundException();
		return Class.forName(className).getConstructor(param1.getClass(), param2.getClass()).newInstance(param1, param2);
	}
	
	/**
	 * Accessor.
	 * @return The MDM service property.
	 */
	public static String getProperty(String key) {
		return instance.getProperty(key);
	}
}
