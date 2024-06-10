package com.vnpt.cryptography.x509;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.util.encoders.Hex;

public class ProcessValidateSignatureECC {

	private static String publicKey = null;
	private static String privateKey = null;

	public static void main(String[] args) throws Exception {
		String path = "./keystore-ecc-p12/keystore-ecc.p12";
		String pass = "123456";
		try {
			System.out.println("----------------------Get-Cert----------------------------------");
			String base64Cert = CertToBase64(path, pass);
			System.out.println("Base64Cert: " + base64Cert);
			X509Certificate cert = Base64ToCert(base64Cert);
			System.out.println("Algorithm: " + cert.getSigAlgName());
			keys(path, pass);
			System.out.println("-------------------Signature-DataClient--------------------------");
			String dataClient = "HelloWorld";
			byte[] byteDataClient = dataClient.getBytes(StandardCharsets.UTF_8);
			MessageDigest mdSHA256 = MessageDigest.getInstance("SHA-256");
			byte[] hashDataClient = mdSHA256.digest(byteDataClient);
			//
			Security.addProvider(new BouncyCastleProvider());
			KeyFactory factory = KeyFactory.getInstance("EC", "BC");
			//
			byte[] priEccByte = Base64.getDecoder().decode(privateKey);
			PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(priEccByte);
			PrivateKey privateKeyECDSA = factory.generatePrivate(encodedKeySpec);
			//
			byte[] signatureDataClient = sign(privateKeyECDSA, dataClient);
			String encoderSignatureDataClientString = Base64.getEncoder().encodeToString(signatureDataClient);
			System.out.println("Signature Data Client String: " + encoderSignatureDataClientString);
			//
			System.out.println("-------------------------Verifier---------------------------------");
			String serverClient = "HelloWorld";
			byte[] signatureDataServer = Base64.getDecoder().decode(encoderSignatureDataClientString);
			byte[] pubEccByte = Base64.getDecoder().decode(publicKey);
			X509EncodedKeySpec encodedPubEccByte = new X509EncodedKeySpec(pubEccByte);
			PublicKey publicKeyECDSA = factory.generatePublic(encodedPubEccByte);
			//
			System.out.println("Validate on server: " + verify(publicKeyECDSA, serverClient, signatureDataServer));
			//
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());

			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}

	public static byte[] sign(PrivateKey privateKey, String message) {
		Signature signature;
		try {
			signature = Signature.getInstance("ECDSA", "BC");
			signature.initSign(privateKey);
			signature.update(message.getBytes());
			return signature.sign();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public static boolean verify(PublicKey publicKey, String message, byte[] signature) {

		try {
			Signature algorithm = Signature.getInstance("ECDSA", "BC");
			algorithm.initVerify(publicKey);
			algorithm.update(message.getBytes());
			return algorithm.verify(signature);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	public static void keys(String keystorePath, String keystorePass) {
		try {
			KeyStore ks = initCrypto(keystorePath, keystorePass);
			String alias = "";
			if (ks.aliases().hasMoreElements()) {
				alias = ks.aliases().nextElement();
			}
			privateKey = Base64.getEncoder().encodeToString(ks.getKey(alias, keystorePass.toCharArray()).getEncoded());
			//
			PublicKey keys = ks.getCertificate(alias).getPublicKey();
			//
			publicKey = Base64.getEncoder().encodeToString(keys.getEncoded());

			//
			System.out.println("PublicKey: " + publicKey);
			System.out.println("PrivateKey: " + privateKey);
			//

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public static KeyStore initCrypto(String keystorePath, String keystorePass) {
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(new FileInputStream(keystorePath), keystorePass.toCharArray());
			return ks;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	public static String CertToBase64(String keystorePath, String keystorePass)
			throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
		X509Certificate cert = null;
		KeyStore p12 = KeyStore.getInstance("pkcs12");
		p12.load(new FileInputStream(keystorePath), keystorePass.toCharArray());
		Enumeration<String> e = p12.aliases();
		while (e.hasMoreElements()) {
			String alias = e.nextElement();
			cert = (X509Certificate) p12.getCertificate(alias);
		}
		return Base64.getEncoder().encodeToString(cert.getEncoded());
	}

	public static X509Certificate Base64ToCert(String certBase64)
			throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
		byte encodedCert[] = Base64.getDecoder().decode(certBase64);
		ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) certFactory.generateCertificate(inputStream);
		return cert;
	}
}
