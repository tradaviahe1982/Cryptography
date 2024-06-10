package com.vnpt.cryptography.x509;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

public class CheckCert {

	public static void main(String[] args)
			throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
		// TODO Auto-generated method stub
		//String base64Cert = "MIICDzCCAbWgAwIBAgIGAY/2mZPQMAoGCCqGSM49BAMCMIGDMSMwIQYDVQQDDBpDbyBxdWFuIGNoaW5oIHRodWMgc28gVk5QVDEYMBYGA1UECgwPQ29uZyB0eSBWTlBULUlUMQ8wDQYDVQQHDAZIYSBOb2kxETAPBgNVBAgMCFZpZXQgTmFtMR4wHAYDVQQGExVUcnVuZyB04m0gVk5QVC1JVCBLVjEwHhcNMjQwNjA4MDY0NjUxWhcNMjUwNjA4MDY0NjUxWjCBgzEjMCEGA1UEAwwaQ28gcXVhbiBjaGluaCB0aHVjIHNvIFZOUFQxGDAWBgNVBAoMD0NvbmcgdHkgVk5QVC1JVDEPMA0GA1UEBwwGSGEgTm9pMREwDwYDVQQIDAhWaWV0IE5hbTEeMBwGA1UEBhMVVHJ1bmcgdOJtIFZOUFQtSVQgS1YxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExirI2a+Y/IlrdP0nlZDpyDsyPkRyFz8hYOUckKk9FTz5eUHf8NqkgM8vowQn6KwKPsLVJfHUh9bdx+RVMXO+0KMTMBEwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiAZ0o6vL+tDx+jteAd4FdZuiQk3P5hMlV9xkeLQMbKXagIhAJvr6tSMzZIjHkBHNWspUaoGO93Nqyr+7B22m56v/FrX";
		//
		String base64Cert = "MIICDzCCAbWgAwIBAgIGAY//y58YMAoGCCqGSM49BAMCMIGDMSMwIQYDVQQDDBpDbyBxdWFuIGNoaW5oIHRodWMgc28gVk5QVDEYMBYGA1UECgwPQ29uZyB0eSBWTlBULUlUMQ8wDQYDVQQHDAZIYSBOb2kxETAPBgNVBAgMCFZpZXQgTmFtMR4wHAYDVQQGExVUcnVuZyB04m0gVk5QVC1JVCBLVjEwHhcNMjQwNjEwMDEzODA1WhcNMjUwNjEwMDEzODA1WjCBgzEjMCEGA1UEAwwaQ28gcXVhbiBjaGluaCB0aHVjIHNvIFZOUFQxGDAWBgNVBAoMD0NvbmcgdHkgVk5QVC1JVDEPMA0GA1UEBwwGSGEgTm9pMREwDwYDVQQIDAhWaWV0IE5hbTEeMBwGA1UEBhMVVHJ1bmcgdOJtIFZOUFQtSVQgS1YxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQ8ZQC+SvewawJu5/ZOWIcb7MrNRRUUotx+PBbJkX/wk/DgDmH5uFns2MrOaPbpzma4FftdlXMQvl2OFabOiPRqMTMBEwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA7Yb2ZSdrOL5Lf8Ijb4JvWSQqDeNceLUf7xqPI05iI/ACIArxUQOcLsMrE/TxEFqqOoQan8ZCvZmXGOg4iOmM4i62";
		//
		X509Certificate cert = Base64ToCert(base64Cert);
		//
		PublicKey publicKey = cert.getPublicKey();
		String base64PublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		//
		System.out.println("Alogorithm: " + cert.getSigAlgName());
		System.out.println("Public Key: " + base64PublicKey);
		System.out.println("Basic Constraints: " + cert.getBasicConstraints());
		System.out.println("Sig Alg OID: " + cert.getSigAlgOID());
		System.out.println("Type: " + cert.getType());
		System.out.println("Version: " + cert.getVersion());
		System.out.println("Critical Extension OIDs: " + cert.getCriticalExtensionOIDs());
		System.out.println("Extended Key Usage: " + cert.getExtendedKeyUsage());
		System.out.println("IssuerDN: " + cert.getIssuerDN().getName());
		System.out.println("Issuer X500 Principal: " + cert.getIssuerX500Principal().getName());
		System.out.println("Not After: " + cert.getNotAfter());
		System.out.println("Not Before: " + cert.getNotBefore());
		System.out.println("Serial Number: " + cert.getSerialNumber());
		System.out.println("SubjectDN: " + cert.getSubjectDN());
		//

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
