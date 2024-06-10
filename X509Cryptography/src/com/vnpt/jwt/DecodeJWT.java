package com.vnpt.jwt;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.vnpt.create.keypair.rsa.ConvertRSAKeyAndString;

public class DecodeJWT {

	public static void main(String[] args) {
		String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArlqCTWeVCT6LHHZhNg0qaFNmnQRwIKnWUS86JZxTuwdk+sfqHTomcsNJGPC93XgzezAd65rhDTe6caW2wUCesNtYDOf2/Px1/bGrjXmWKMMPAMPa5B584Qprt0wTs6/uAHbUC6k/EpVgzSIJOUZ/q6lyElAYP/SZQaulPMj4b5jgDcWZ1v589Jz/dhK9t29TnawPai8U/O1UbY8ro/idFo0PlKoXzx78OrdyyP9q/YzPbFh5C+oG407EZZLS/fczN1SefIg+fz1trZaDkfhvGUog3oYld5DcrwdTuGWPlyI5akoHYMQS+ifEqeHly34GAgMlD8dcPArADfuBf+9TbwIDAQAB";
		String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCuWoJNZ5UJPoscdmE2DSpoU2adBHAgqdZRLzolnFO7B2T6x+odOiZyw0kY8L3deDN7MB3rmuENN7pxpbbBQJ6w21gM5/b8/HX9sauNeZYoww8Aw9rkHnzhCmu3TBOzr+4AdtQLqT8SlWDNIgk5Rn+rqXISUBg/9JlBq6U8yPhvmOANxZnW/nz0nP92Er23b1OdrA9qLxT87VRtjyuj+J0WjQ+UqhfPHvw6t3LI/2r9jM9sWHkL6gbjTsRlktL99zM3VJ58iD5/PW2tloOR+G8ZSiDehiV3kNyvB1O4ZY+XIjlqSgdgxBL6J8Sp4eXLfgYCAyUPx1w8CsAN+4F/71NvAgMBAAECggEACN4pVQf0Y+Cw6A4fCjO+pttzpaP2kt4nYRux9mpS6+cHqe7PFV3CNyYSKrRuMXNXN4ygiPR69PsAx+dEOi15En+3yXhCSmblX7V1PiAjcFFO5ngPsMG17blj0W2LSUXt37kG7V8xnHsShOoor15c/7RLA/4AUlGQFe+zbV52QOffVk/n0+xutcqeLQHmWH4ni692HhP4lZtx+Gb8RmOgnAcr3iiHm4mbNlxf+l/F2IKrJAL3S5bxO+7pBJJ37cMqgfJLjWqjCilFq5+UkN4UqgpyD+eRMhbhS96w5uFnq7rQsENvHkZSESH2il1nyM27OKwOh4kYfhceZWGalKFIAQKBgQDnBoyoUMj5kxKrE2Zan7mqQBU9o7T62htOPez4g/pUtw6IqrA+66A1yot18raZM2pZKCYl6rIIe2gn18mp3tk8HV3gi3qFCCRnxSEJzXFicYdqgRtFNK8NCmVwilOUvwcfq4X1cD8uKzEc23V8VkjlKgpEWsSsPWGE8SLfsy0UAQKBgQDBM5sVoka720RPvYX1nCRiRWKhu7IxXMJSx4ng6HZuwZM6OB4z/dUhODcssUN1nhO+MuAO40FBoJoT2AEOKFkMZkweEFobRT2ovtA9ccYpOhol4tl2P0yteY8T5M+zuhrqMwLrPkCDut9KB2n/aZIqWNKz/wrp/Lzro9cym1enbwKBgQC5JIWKyhsV76iRU12+mKypZOvg1xZNxocFgBkt3E68n2tVWT0fX6OoGCcFojp1sj+zLbrMvjZpF8UT0Ro7OW1sgLhgIEdS34CVbOSaP3tzgjocv1TEdIEo+UDsHN74oNKrrcEQPiFT9adJUhLoTxniFXve5cMhqZtCeCETlzs0AQKBgF9/LKcS4Te1+BwaJ/7xQSK5/TjIWBoCKaNVMhfTj8bLNATQ/EziqNiUuuECdb/LdSLMbues+PKBeedZG5xt4SY54mHx3zgfj4y7VJ8qf7KdH5Oef7LtMu+EaG6C6Q+DbA5bTJQO30C9u+URqRkwi6kW4n9KD5D89jzbbWF8W2VNAoGAF5dsXjn2tG9772THCkrriQD7047LXp0QFm0BZgbvwRJyuTxqimm+OuvpGn8hmXYA16fhjsIWufUK0tsBCh+IrxMZjavavLoGvChI/2bhQhZqy1n3HtcXnfl6o4jtK3NrJEDCtd1d2w4EA4g9ZzS5ca2pZoDUa9+rjI27xJgLZXw=";
		RSAPublicKey rsaPublicKey = ConvertRSAKeyAndString.convertStringToPublicKey(publicKey);
		RSAPrivateKey rsaPrivateKey = ConvertRSAKeyAndString.convertStringToPrivateKey(privateKey);
		Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, rsaPrivateKey);
		// TODO Auto-generated method stub
		System.out.println("-------------VERIFIER-JWT------------------");
		String tokenJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJJc3N1ZXIiLCJleHAiOjE3NDk1NDEyMTgsInN1YiI6IlN1YmplY3QifQ.biKnfSfaF7WiTJTSbQzn9MhC1rS_H_DvtAJEewpCTYseT0xmjroit1V42EBPsTE8QESMFlYXdOaUI7IF2bPEodNBCT-f4up88r0FUvLN86fD8NGlLpnpGzhUAH664fZaFGoTvpJKb1piGlZwt8yox9zkT-_K7_FR-Q9xjw2JDuGniyEJkjT5pgjw9MKjZV3rDroF23DSVbfk8JiKx2f00A54X01igkzG5gjeolvkPUeteViVzzy2o4ehoAtNrg3suWXf81hYEwYO-F4-zyfZedWFsm3M-wRxqzCupqbjQ3BFCeomkBQx6KQEjSi1W_40wJ5RzkSCRfxuPDlVPzqs6w";
		DecodedJWT decodedJWT;
		try {
			JWTVerifier verifier = JWT.require(algorithm)
					// specify any specific claim validations
					.withIssuer("Issuer")
					// reusable verifier instance
					.build();
			//
			decodedJWT = verifier.verify(tokenJWT);
			//
			System.out.println("Issuer: " + decodedJWT.getIssuer());
			System.out.println("Subject: " + decodedJWT.getSubject());
			System.out.println("ExpiresAt: " + decodedJWT.getExpiresAt());
			System.out.println("Algorithm: " + decodedJWT.getAlgorithm());
		} catch (JWTVerificationException exception) {
			// Invalid signature/claims
		}
	}
}
