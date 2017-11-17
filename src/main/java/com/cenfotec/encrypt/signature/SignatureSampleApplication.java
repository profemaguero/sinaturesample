package com.cenfotec.encrypt.signature;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import org.springframework.boot.Banner;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SignatureSampleApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication  app = new SpringApplication(SignatureSampleApplication.class);
		app.setBannerMode(Banner.Mode.OFF);
		app.run(args);
	}

	@Override
	public void run(String... args) throws Exception {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(1024, random);
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey priv = pair.getPrivate();
		PublicKey pub = pair.getPublic();
		Signature dsa = Signature.getInstance("SHA1withDSA", "SUN"); 
		dsa.initSign(priv);
		FileInputStream fis = new FileInputStream("C:/encrypt/signature/data.file");
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bufin.read(buffer)) >= 0) {
		    dsa.update(buffer, 0, len);
		};
		bufin.close();
		byte[] realSig = dsa.sign();
		//save the signature
		FileOutputStream sigfos = new FileOutputStream("C:/encrypt/signature/sig.file");
		sigfos.write(realSig);
		sigfos.close();
		/* save the public key in a file */
		byte[] key = pub.getEncoded();
		FileOutputStream keyfos = new FileOutputStream("C:/encrypt/signature/suepk.file");
		keyfos.write(key);
		keyfos.close();
		
		// now verify the signature
		//
		//
		
		FileInputStream keyfis = new FileInputStream("C:/encrypt/signature/suepk.file");
		byte[] encKey = new byte[keyfis.available()];  
		keyfis.read(encKey);

		keyfis.close();
		
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
		
		//read the signature
		FileInputStream sigfis = new FileInputStream("C:/encrypt/signature/sig.file");
		byte[] sigToVerify = new byte[sigfis.available()]; 
		sigfis.read(sigToVerify);
		sigfis.close();
		
		Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
		sig.initVerify(pubKey);
		
		FileInputStream datafis = new FileInputStream("C:/encrypt/signature/data.file");
		BufferedInputStream bufin2 = new BufferedInputStream(datafis);

		byte[] buffer2 = new byte[1024];
		int len2;
		while (bufin2.available() != 0) {
		    len2 = bufin2.read(buffer2);
		    sig.update(buffer2, 0, len2);
		};

		bufin2.close();
		
		boolean verifies = sig.verify(sigToVerify);

		System.out.println("signature verifies: " + verifies);
	}
}
