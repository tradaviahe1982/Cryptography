package com.vnpt.create.keypair.ecc;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class GetInfomationKeyPair {

	public static void main(String[] args)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {

		Security.addProvider(new BouncyCastleProvider());
		KeyFactory factory = KeyFactory.getInstance("EC", "BC");
		String publicKeyECC = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQ8ZQC+SvewawJu5/ZOWIcb7MrNRRUUotx+PBbJkX/wk/DgDmH5uFns2MrOaPbpzma4FftdlXMQvl2OFabOiPRg==";
		String privateKeyECC = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgW8kUmjIZqiOGc9jWof9DmBbWT7tu6fw3Tn8A+PDUa22gCgYIKoZIzj0DAQehRANCAARDxlAL5K97BrAm7n9k5Yhxvsys1FFRSi3H48FsmRf/CT8OAOYfm4WezYys5o9unOZrgV+12VcxC+XY4Vps6I9G";
		//
		byte[] priEccByte = Base64.getDecoder().decode(privateKeyECC);
		PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(priEccByte);
		PrivateKey privateKeyEC = factory.generatePrivate(encodedKeySpec);
		System.out.println("Private Key: " + Base64.getEncoder().encodeToString(privateKeyEC.getEncoded()));
		//
		byte[] pubEccByte = Base64.getDecoder().decode(publicKeyECC);
		X509EncodedKeySpec encodedPubEccByte = new X509EncodedKeySpec(pubEccByte);
		PublicKey publicKeyEC = factory.generatePublic(encodedPubEccByte);
		System.out.println("Public Key: " + Base64.getEncoder().encodeToString(publicKeyEC.getEncoded())); //
		//
		CreateKeyPairEC.writeFile("./ecc-dir/id_ecc_private_key.key",
				Base64.getEncoder().encode(privateKeyEC.getEncoded()));
		CreateKeyPairEC.writeFile("./ecc-dir/id_ecc_public_key.pem",
				Base64.getEncoder().encode(publicKeyEC.getEncoded()));
		
	}
}
