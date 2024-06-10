package com.vnpt.test;

import java.security.Provider;
import java.security.Security;

public class Test {
	public static void main(String[] args) {
		Provider[] installedProvs = Security.getProviders();

		for (int i = 0; i != installedProvs.length; i++) {
			System.out.print(installedProvs[i].getName());
			System.out.print(": ");
			System.out.print(installedProvs[i].getInfo());
			System.out.println();
		}
	}
}
