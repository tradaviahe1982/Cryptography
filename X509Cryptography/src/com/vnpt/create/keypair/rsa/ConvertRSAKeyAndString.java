package com.vnpt.create.keypair.rsa;

import java.io.File;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.apache.commons.io.FileUtils;

public class ConvertRSAKeyAndString {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.out.println("Public Key: " + convertPublicKeyToString("./rsa-dir/id_rsa_public_key.pem"));
		System.out.println("Private Key: " + convertPrivateKeyToString("./rsa-dir/id_rsa_private_key.key"));
	}

	public static String convertPrivateKeyToString(String pathFileName) {
		String result = null;
		File file = new File(pathFileName);
		try {
			result = FileUtils.readFileToString(file, "UTF-8");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			result = null;
		}
		return result;
	}

	public static String convertPublicKeyToString(String pathFileName) {
		String result = null;
		File file = new File(pathFileName);
		try {
			result = FileUtils.readFileToString(file, "UTF-8");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			result = null;
		}
		return result;
	}

	public static RSAPrivateKey convertStringToPrivateKey(String contentPrivateKey) {
		KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		RSAPrivateKey privateKey = null;
		PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(contentPrivateKey));
		try {
			privateKey = (RSAPrivateKey) kf.generatePrivate(keySpecPKCS8);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return privateKey;
	}

	public static RSAPublicKey convertStringToPublicKey(String contentPublicKey) {
		KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(contentPublicKey));
		RSAPublicKey pubKey = null;
		try {
			pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return pubKey;
	}

}
