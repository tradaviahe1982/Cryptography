package com.vnpt.cryptography.x509.create.cert.ecc;

import java.io.FileOutputStream;
import java.security.KeyStore;

import com.vnpt.cryptography.x509.create.cert.rsa.KeyStoreGenRSA;

public class CreateCertEC {
	//
	public static void main(String[] args) throws Exception {
		final KeyStore keyStore = KeyStoreGenEC.generatePKCS12KeyStore("123456");
		final FileOutputStream fos = new FileOutputStream("./keystore-ecc-p12/keystore-ecc.p12");
		keyStore.store(fos, "123456".toCharArray());
		System.out.println("Tạo cert thành công!!!");
	}
}