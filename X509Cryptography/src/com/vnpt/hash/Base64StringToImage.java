package com.vnpt.hash;

import java.io.File;
import java.io.IOException;
import java.util.Base64;

import org.apache.commons.io.FileUtils;

public class Base64StringToImage {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		byte[] fileContent = null;
		try {
			fileContent = FileUtils.readFileToByteArray(new File("./images/A-Cat.jpg"));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String encodedString = Base64.getEncoder().encodeToString(fileContent);
		//
		byte[] decodedBytes = Base64.getDecoder().decode(encodedString);
		try {
			FileUtils.writeByteArrayToFile(new File("./images/A-Cat-Copy.jpg"), decodedBytes);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
