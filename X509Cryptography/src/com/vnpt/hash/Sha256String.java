package com.vnpt.hash;

import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.digest.DigestUtils;

import com.google.common.hash.Hashing;

public class Sha256String {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String originalString = "Xin chào bạn Nguyễn Việt Anh!";
		//
		String sha256hex = Hashing.sha256().hashString(originalString, StandardCharsets.UTF_8).toString();
		String sha256hex1 = DigestUtils.sha256Hex(originalString);
		System.out.println(sha256hex);
		System.out.println(sha256hex1);
		String sha512hex = Hashing.sha512().hashString(originalString, StandardCharsets.UTF_8).toString();
		System.out.println(sha512hex);
	}

}
