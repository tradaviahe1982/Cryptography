package com.vnpt.create.keypair.rsa;

public class GenerateKeyPairRSA {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			RSAUtils.generateKey("./rsa-dir/id_rsa_public_key.pem", "./rsa-dir/id_rsa_private_key.key",
					"0711198215071988", 0);
			System.out.println("Create Key Pair RSA Success!!!");
			//
			// RSAPublicKey publicKey = (RSAPublicKey)
			// RSAUtils.getPublicKey("./text-file/id_rsa_public_key.pem");
			// RSAPrivateKey privateKey = (RSAPrivateKey)
			// RSAUtils.getPrivateKey("./text-file/id_rsa_private_key.key");
			//
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Create Key Pair Fail!!!");
		}
	}

}
