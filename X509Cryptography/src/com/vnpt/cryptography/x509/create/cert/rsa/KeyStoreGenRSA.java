package com.vnpt.cryptography.x509.create.cert.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import javax.crypto.KeyGenerator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class KeyStoreGenRSA {
	public static final String ENCRYPT_ALGORITHM = "RSA";

	private static final int DEFAULT_KEY_SIZE = 2048;

	
	public static KeyStore generatePKCS12KeyStore(final String password) throws KeyStoreException,
			NoSuchAlgorithmException, IOException, CertificateException, OperatorCreationException {
		final KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(null, password.toCharArray());

		String secret = "password";
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ENCRYPT_ALGORITHM);
		SecureRandom secureRandom = new SecureRandom(secret.getBytes());
		keyPairGenerator.initialize(Math.max(0, DEFAULT_KEY_SIZE), secureRandom);
		final KeyPair asymmetricKeys = keyPairGenerator.genKeyPair();
		//
		final KeyStore.PrivateKeyEntry privateKey = new KeyStore.PrivateKeyEntry(asymmetricKeys.getPrivate(),
				new X509Certificate[] { generateX509Certificate(asymmetricKeys) });
		//
		final KeyStore.ProtectionParameter privateKeyPassword = new KeyStore.PasswordProtection(password.toCharArray());
		// Add asymmetric key to keystore
		keyStore.setEntry("vnpt", privateKey, privateKeyPassword);

		return keyStore;
	}

	private static X509Certificate generateX509Certificate(final KeyPair keyPair)
			throws OperatorCreationException, CertificateException, CertIOException {
		final Instant now = Instant.now();
		final Date notBefore = Date.from(now);
		final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));

		final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());

		// IssuerDN: CN=Co quan chung thuc so Chinh phu, O=Ban Co yeu Chinh phu, C=VN
		final X500Name x500Name = new X500Name(
				"CN=Co quan chinh thuc so VNPT, O=Cong ty VNPT-IT, L=Ha Noi, ST=Viet Nam, C=Trung tâm VNPT-IT KV1");
		// subjects name - the same as we are self signed.

		final X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(x500Name,
				BigInteger.valueOf(now.toEpochMilli()), 
				notBefore, 
				notAfter, 
				x500Name, 
				keyPair.getPublic())
				.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

		return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
				.getCertificate(certificateBuilder.build(contentSigner));
	}
}