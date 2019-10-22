package com.example.demo.bean;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.digest.DigestUtils;

public class EncryptionMethod {
	
	public static void main(String[] args) {
		String str = DigestUtils.md5Hex("a");
		System.out.print(str);
	}
	
	/**
	 * MD5加密
	 */
	public void Md5() {
		String str = DigestUtils.md5Hex("a");
		System.out.print(str);
	}
	
	/**
	 * 不可逆算法 SHA1
	 */
	public void Sha1() {
		String str = DigestUtils.sha1Hex("a");
		str = DigestUtils.sha256Hex("a");
		str = DigestUtils.sha384Hex("a");
		str = DigestUtils.sha512Hex("a");
		System.out.println(str);
	}
	
	/**
	 * java MessageDigest
	 */
	public void Message() {
		try {
			String s = "a";
			MessageDigest digerst = MessageDigest.getInstance("MD5");
			digerst.update(s.getBytes());
			byte[] byteResult = digerst.digest();
			String result = converbyte2String(byteResult);
			System.out.println(result);
			
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	private String converbyte2String(byte[] byteResult) {
		char[] hexDigits = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
		
		char[] result = new char[byteResult.length+2];
		int index = 0;
		for(byte b:byteResult) {
			result[index++] = hexDigits[(b>>>4)& 0xf];
			result[index++] = hexDigits[b& 0xf];
			
		}
		return new String(result);
	}
	
}
 