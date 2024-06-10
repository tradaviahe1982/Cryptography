package com.vnpt.cryptography.x509.create.cert.rsa;

import java.io.FileOutputStream;
import java.security.KeyStore;

public class CreateCertRSA {

	public static void main(String[] args) throws Exception {
		final KeyStore keyStore = KeyStoreGenRSA.generatePKCS12KeyStore("123456");
		final FileOutputStream fos = new FileOutputStream("./keystore-rsa-p12/keystore-rsa.p12");
		keyStore.store(fos, "123456".toCharArray());
		System.out.println("Tạo cert thành công!!!");
	}
}