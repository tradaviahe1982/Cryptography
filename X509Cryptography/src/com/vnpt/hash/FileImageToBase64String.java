package com.vnpt.hash;

import java.io.File;
import java.io.IOException;
import java.util.Base64;

import org.apache.commons.io.FileUtils;

public class FileImageToBase64String {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			byte[] fileContent = FileUtils.readFileToByteArray(new File("./text-file/A-Cat.jpg"));
			String encodedString = Base64.getEncoder().encodeToString(fileContent);
			System.out.println(encodedString);
		} catch (IOException e) {
			System.out.println("Error!");
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
