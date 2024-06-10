package com.vnpt.cryptography.x509;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class ProcessValidateSignatureRSA {

	private static String publicKey = null;
	private static String privateKey = null;

	public static void main(String[] args)
			throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {
		String path = "./keystore-rsa-p12/keystore-rsa.p12";
		String pass = "123456";
		try {
			System.out.println("--------------------------------Get-Cert------------------------------------");
			String base64Cert = CertToBase64(path, pass);
			System.out.println("Base64Cert: " + base64Cert);
			X509Certificate cert = Base64ToCert(base64Cert);
			System.out.println("Algorithm: " + cert.getSigAlgName());
			keys(path, pass);
			System.out.println(
					"--------------------------------Signature-DataClient------------------------------------");
			String dataClient = "HelloWorld";
			byte[] byteDataClient = dataClient.getBytes(StandardCharsets.UTF_8);
			MessageDigest mdSHA256 = MessageDigest.getInstance("SHA-256");
			byte[] hashDataClient = mdSHA256.digest(byteDataClient);
			byte[] signatureDataClient = client(hashDataClient, getPrivateKey(privateKey));
			String encoderSignatureDataClientString = Base64.getEncoder().encodeToString(signatureDataClient);
			System.out.println("Signature Data Client String: " + encoderSignatureDataClientString);
			//
			System.out.println("--------------------------------Verifier------------------------------------");
			String dataServer = "HelloWorld";
			byte[] byteDataServer = dataServer.getBytes(StandardCharsets.UTF_8);
			byte[] hashDataServer = mdSHA256.digest(byteDataServer);
			byte[] decodedSignature = Base64.getDecoder().decode(encoderSignatureDataClientString);
			byte[] serverHashDecrypt = server(decodedSignature, publicKey);
			//
			boolean validate = validate(serverHashDecrypt, hashDataServer);
			System.out.println("Validate on server: " + validate);
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

	/**
	 * @param messageHash
	 * @param privateKey
	 * @return
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static byte[] client(byte[] messageHash, PrivateKey privateKey)
			throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException,
			NoSuchAlgorithmException, IOException {
		// Client
		DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
		AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find("SHA-256");
		DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, messageHash);
		byte[] hashToEncrypt = digestInfo.getEncoded();

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		byte[] encryptedMessageHash = cipher.doFinal(hashToEncrypt);

		return encryptedMessageHash;
	}

	/**
	 * @param encryptedMessageHash
	 * @param publicKey
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public static byte[] server(byte[] encryptedMessageHash, String publicKey) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
		// Server
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, getPublicKey(publicKey));
		byte[] decryptedMessageHash = cipher.doFinal(encryptedMessageHash);
		return decryptedMessageHash;
	}

	/**
	 * @param decryptedMessageHash
	 * @param newMessageHash
	 * @return
	 * @throws IOException
	 */
	public static boolean validate(byte[] decryptedMessageHash, byte[] newMessageHash) throws IOException {
		DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
		AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find("SHA-256");
		DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, newMessageHash);
		byte[] hashToEncrypt = digestInfo.getEncoded();

		String sha256hex = new String(Hex.encode(decryptedMessageHash));
		System.out.println("sha256 data decrypted server: " + sha256hex);

		sha256hex = new String(Hex.encode(hashToEncrypt));
		System.out.println("sha256 data client          : " + sha256hex);

		return Arrays.equals(decryptedMessageHash, hashToEncrypt);
	}

	/**
	 * @param keystorePath
	 * @param keystorePass
	 */
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

	/**
	 * @param keystorePath
	 * @param keystorePass
	 * @return
	 */
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

	/**
	 * @param base64PublicKey
	 * @return
	 */
	public static PublicKey getPublicKey(String base64PublicKey) {
		PublicKey publicKey = null;
		try {
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKey = keyFactory.generatePublic(keySpec);
			return publicKey;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return publicKey;
	}

	/**
	 * @param base64PrivateKey
	 * @return
	 */
	public static PrivateKey getPrivateKey(String base64PrivateKey) {
		PrivateKey privateKey = null;
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		try {
			privateKey = keyFactory.generatePrivate(keySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return privateKey;
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
