package com.vnpt.hash;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;

public class FileToBase64String {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		File file = new File("./text-file/hello.txt");
		byte[] encoded = null;
		try {
			encoded = Base64.encodeBase64(FileUtils.readFileToByteArray(file));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String result = new String(encoded, StandardCharsets.UTF_8);
		System.out.println(result);
		//
		byte[] decodedBytes = Base64.decodeBase64(result);
		try {
			FileUtils.writeByteArrayToFile(new File("./text-file/hello-copy.txt"), decodedBytes);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//
	}

}
