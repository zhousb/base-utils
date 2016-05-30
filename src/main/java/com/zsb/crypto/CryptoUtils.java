package com.zsb.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

/**
 * 加解密工具类 Date: 2016年4月12日 <br>
 * 
 * @author zhoushanbin
 * 
 */
public final class CryptoUtils {
	
	/**
	 * aes 加密模式为AES/CBC/PKCS5Padding
	 */
	public static final String AES_CBC_PAD = "AES/CBC/PKCS5Padding";
	
	/**
	 * AES
	 */
	public static final String AES = "AES";
	/**
	 * 初始化向量长度
	 */
	public static final int IV_LENGTH = 16;
	
	/**
	 * 编码方式
	 */
	public static final String UTF_8 = "utf-8";
	
	/**
	 * 工作密钥 16字节数组
	 */
	public static final byte[] WORK_KEY = { (byte) 0x11, (byte) 0x22,
			(byte) 0x33, (byte) 0x22, (byte) 0x13, (byte) 0xff, (byte) 0xee,
			(byte) 0x44, (byte) 0xaa, (byte) 0xcc, (byte) 0x16, (byte) 0x57,
			(byte) 0x00, (byte) 0x40, (byte) 0xba, (byte) 0xbe, };

	
	/**
	 * 加密
	 * @param content
	 * @return
	 */
	public static String encrypt(String content) {
		
		if(StringUtils.isEmpty(content)){
			return null;
		}
		
		SecretKeySpec skeySpec = new SecretKeySpec(WORK_KEY, AES);
		Cipher cipher = null;
		byte []result  = null;
		String afCnt = null;
		try {
			cipher = Cipher.getInstance(AES_CBC_PAD);
			byte []iv = getIv();
			
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
			byte[] cnt = cipher.doFinal(content.getBytes());
			
			result = new byte[cnt.length+IV_LENGTH];
			System.arraycopy(iv, 0, result, 0, iv.length);
			System.arraycopy(cnt, 0, result, IV_LENGTH, cnt.length);
			afCnt = new String(Base64.encodeBase64(result),UTF_8);
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		return afCnt;
	}
	
	/**
	 * 解密
	 * @param content
	 * @return
	 */
	public static String decrypt(String content) {
		
		if(StringUtils.isEmpty(content)){
			return null;
		}
		try {
			byte[] acnt = content.getBytes(UTF_8);
			
			byte[] bcnt = Base64.decodeBase64(acnt);
			
			byte []iv = new byte[IV_LENGTH];
			byte []cnt = new byte[bcnt.length-IV_LENGTH];
			System.arraycopy(bcnt, 0, iv, 0, IV_LENGTH); 
			System.arraycopy(bcnt, IV_LENGTH, cnt, 0, bcnt.length-IV_LENGTH);
			
			//进行解密操作
			SecretKeySpec skeySpec = new SecretKeySpec(WORK_KEY, AES);
			Cipher cipher = Cipher.getInstance(AES_CBC_PAD);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
			byte[] original = cipher.doFinal(cnt);
			return new String(original,UTF_8);
			
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	/**
	 * 获取初始化向量 16个字节
	 * @return
	 */
	private static byte[] getIv(){
		SecureRandom random = new SecureRandom();
		byte []iv = new byte[IV_LENGTH];
		random.nextBytes(iv);
		return iv;
	}
		
	public static void main(String args[]){

		String str1 = encrypt("Admin@1234eeee");
		System.out.println(str1);	
		System.out.println(decrypt(str1));
	}
	
}
