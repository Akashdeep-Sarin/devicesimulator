package com.akash.devicesimulator.util;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.springframework.core.io.ClassPathResource;

public class Utility {
	private static final String PropertyFile = "/config.properties";

	public static class KeyStorePasswordPair {
		public KeyStore keyStore;
		public String keyPassword;

		public KeyStorePasswordPair(KeyStore keyStore, String keyPassword) {
			this.keyStore = keyStore;
			this.keyPassword = keyPassword;
		}
	}

	public static String getConfig(String name) {
		Properties prop = new Properties();
		
		URL resource = null;
		try {
			resource = new ClassPathResource(PropertyFile).getURL();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		if (resource == null) {
			return null;
		}
		
		try (InputStream stream = resource.openStream()) {
			prop.load(stream);
		} catch (IOException e) {
			return null;
		}
		
		String value = prop.getProperty(name);
		if (value == null || value.trim().length() == 0) {
			return null;
		} else {
			return value;
		}
	}

	public static KeyStorePasswordPair getKeyStorePasswordPair(final String certificateFile,
			final String privateKeyFile) {
		return getKeyStorePasswordPair(certificateFile, privateKeyFile, null);
	}

	public static KeyStorePasswordPair getKeyStorePasswordPair(final String certificateFile,
			final String privateKeyFile, String keyAlgorithm) {
		if (certificateFile == null || privateKeyFile == null) {
			System.out.println("Certificate or private key file missing");
			return null;
		}
		System.out.println("Cert file:" + certificateFile + " Private key: " + privateKeyFile);

		final PrivateKey privateKey = loadPrivateKeyFromFile(privateKeyFile, keyAlgorithm);

		final List<Certificate> certChain = loadCertificatesFromFile(certificateFile);

		if (certChain == null || privateKey == null)
			return null;

		return getKeyStorePasswordPair(certChain, privateKey);
	}

	public static KeyStorePasswordPair getKeyStorePasswordPair(final List<Certificate> certificates,
			final PrivateKey privateKey) {
		KeyStore keyStore;
		String keyPassword;
		try {
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null);

			// randomly generated key password for the key in the KeyStore
			keyPassword = new BigInteger(128, new SecureRandom()).toString(32);

			Certificate[] certChain = new Certificate[certificates.size()];
			certChain = certificates.toArray(certChain);
			keyStore.setKeyEntry("alias", privateKey, keyPassword.toCharArray(), certChain);
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			System.out.println("Failed to create key store");
			return null;
		}

		return new KeyStorePasswordPair(keyStore, keyPassword);
	}

	private static List<Certificate> loadCertificatesFromFile(final String filename) {

		InputStream resource = null;
		try {
			resource = new ClassPathResource(filename).getInputStream();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		if (resource == null) {
			System.out.println("Certificate file: " + filename + " is not found.");
			return null;
		}

		try (BufferedInputStream stream = new BufferedInputStream(resource)) {
			final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			return (new ArrayList<Certificate>(certFactory.generateCertificates(stream)));
		} catch (IOException | CertificateException e) {
			System.out.println("Failed to load certificate file " + filename);
		}
		return null;
	}

	private static PrivateKey loadPrivateKeyFromFile(final String filename, final String algorithm) {
		
		PrivateKey privateKey = null;

		InputStream inputStream = null;
		try {
			inputStream = new ClassPathResource(filename).getInputStream();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
			
		try (DataInputStream stream = new DataInputStream(inputStream)) {
			privateKey = PrivateKeyReader.getPrivateKey(stream, algorithm);
		} catch (IOException | GeneralSecurityException e) {
			System.out.println("Failed to load private key from file " + filename);
		}

		return privateKey;
	}

}
