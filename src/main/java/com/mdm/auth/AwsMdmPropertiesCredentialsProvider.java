/**
 * 
 */
package com.mdm.auth;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.mdm.utils.MdmServiceKey;
import com.mdm.utils.MdmServiceProperties;

/**
 * AWS Credentials Provider using the MdmServiceProperties.
 * @author paul
 */
public class AwsMdmPropertiesCredentialsProvider implements
		AWSCredentialsProvider {
	private String secretKey;
	private String accessKey;

	public AwsMdmPropertiesCredentialsProvider() {
		refresh();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AWSCredentials getCredentials() {
		return new BasicAWSCredentials(accessKey, secretKey);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void refresh() {
		secretKey = MdmServiceProperties.getProperty(MdmServiceKey.awsSecretKey);
		accessKey = MdmServiceProperties.getProperty(MdmServiceKey.awsAccessKeyId);
	}

}
