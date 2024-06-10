package com.vnpt.create.keypair.ecc;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

public class CreateKeyPairEC {

	// public key (x,y) and the private key (256 bit)
	public static KeyPair generateKeys(String algorithm, String provider) {
		try {
			KeyPairGenerator  kpGen = KeyPairGenerator.getInstance(algorithm, provider);
			kpGen.initialize(new ECGenParameterSpec("P-256"));
		    return kpGen.generateKeyPair();
			//
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public static void writeFile(String filename, byte[] bytes) throws IOException {
		File file = new File(filename);
		File fileParent = file.getParentFile();
		if (!file.exists()) {
			if (!fileParent.exists()) {
				fileParent.mkdirs();
			}
			file.createNewFile();
		}
		Files.write(file.toPath(), bytes);
	}
}