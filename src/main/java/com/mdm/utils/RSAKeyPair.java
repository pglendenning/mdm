package com.mdm.utils;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSAKeyPair {

	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;;
	private PublicKey pubKey = null;
	private PrivateKey privKey = null;
	private int rsaKeySize = 2048;
	
	public RSAKeyPair() {
	}
	
	public RSAKeyPair(int keySize) {
		rsaKeySize = keySize;
	}
	
	public PublicKey getPublicKey() {
		return pubKey;
	}
	
	public PrivateKey getPrivateKey() {
		return privKey;
	}
	
	public void generate(RSAPrivateCrtKeySpec privKeySpec, RSAPublicKeySpec pubKeySpec) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		KeyFactory fact = KeyFactory.getInstance("RSA", BC);
        privKey = fact.generatePrivate(privKeySpec);
        pubKey = fact.generatePublic(pubKeySpec);
	}
	
	public void generate() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        if (rsaKeySize == 2048) {
	        generator.init(new RSAKeyGenerationParameters
	            (
	                new BigInteger("10001", 16),//publicExponent
	                SecureRandom.getInstance("SHA1PRNG"),//prng
	                2048,//strength
	                112	 //certainty
	            ));
        } else if (rsaKeySize == 1024){
	        generator.init(new RSAKeyGenerationParameters
		            (
		                new BigInteger("10001", 16),//publicExponent
		                SecureRandom.getInstance("SHA1PRNG"),//prng
		                1024,//strength
		                80	 //certainty
		            ));        	
        } else {
        	throw new InvalidKeySpecException();
        }

        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        
		RSAKeyParameters publicKey = (RSAKeyParameters) keypair.getPublic();
		RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keypair.getPrivate();
		// Must use the BC factory else we can't cast privKey to a PKCS12BagAttributeCarrier 
        KeyFactory fact = KeyFactory.getInstance("RSA", BC);
		pubKey = fact.generatePublic(
				new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getExponent()));
		privKey = fact.generatePrivate(
				new RSAPrivateCrtKeySpec(publicKey.getModulus(), publicKey.getExponent(),
						privateKey.getExponent(), privateKey.getP(), privateKey.getQ(), 
						privateKey.getDP(), privateKey.getDQ(), privateKey.getQInv()));
    }
}
