package com.github.k4czp3r.tapop100;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;
import java.util.Optional;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.k4czp3r.tapop100.domain.HandshakeResponse;
import com.github.k4czp3r.tapop100.domain.KspKeyPair;
import com.google.gson.JsonObject;


public class Main {

	private final static Logger LOG = LoggerFactory.getLogger(Main.class);

	public static void main(String[] args) throws Exception {

		Properties prop = new Properties();
		File f = new File("tapop100.properties");

		if (!f.exists()) {
			boolean newFile = f.createNewFile();

			if (newFile) {
				LOG.debug("new tapop100.properties file created");
			}
		}

		try (FileInputStream s = new FileInputStream("tapop100.properties")) {
			prop.load(s);
		}

		Optional<String> maybeIP = Optional.ofNullable(prop.getProperty("ip")).filter(s -> !s.equals("null"));
		Optional<String> maybeEmail = Optional.ofNullable(prop.getProperty("email")).filter(s -> !s.equals("null"));
		Optional<String> maybePassword = Optional.ofNullable(prop.getProperty("password")).filter(s -> !s.equals("null"));

		if (maybeIP.isEmpty()) {
			LOG.warn("No IP of PowerPlug specified. Please adjust tapop100.properties");
		}

		if (maybeEmail.isEmpty()) {
			LOG.warn("No TP-Email-Address specified. Please adjust tapop100.properties");
		}

		if (maybePassword.isEmpty()) {
			LOG.warn("No Password for the Email-Address specified. Please adjust tapop100.properties");
		}

		prop.put("ip", maybeIP.orElse("null"));
		prop.put("email", maybeEmail.orElse("null"));
		prop.put("password", maybePassword.orElse("null"));

		try (FileOutputStream s = new FileOutputStream("tapop100.properties")) {
			prop.store(s, "");
		}

		if (maybeIP.isEmpty() || maybeEmail.isEmpty() || maybePassword.isEmpty()) {
			LOG.warn("script not configured, please adjust tapop100.properties and try again");
			System.exit(1);
		}

		final String ip = maybeIP.get();
		final String email = maybeEmail.get();
		final String password = maybePassword.get();

		if (args.length < 1) {
			System.out.println("Please provide parameters to this script, e.g. to turn on the switch: ");
			System.out.println("java -jar tapop100-1.0-SNAPSHOT-jar-with-dependencies.jar true");
			System.out.println("to turn it off: ");
			System.out.println("java -jar tapop100-1.0-SNAPSHOT-jar-with-dependencies.jar false");
			System.exit(1);
		}

		boolean enabled = Boolean.parseBoolean(args[0]);

		Security.addProvider(new BouncyCastleProvider());
		LOG.info("Generating keypair...");
		TapoFlow tapoFlow = new TapoFlow(ip);

		KspKeyPair kspKeyPair = KspEncryption.generateKeyPair();


		LOG.info("Sending handshake...");
		HandshakeResponse handshakeResponse = tapoFlow.makeHandshake(kspKeyPair);
		if (handshakeResponse == null) {
			System.exit(1);
		}


		String keyFromTapo = handshakeResponse.getResponse().getAsJsonObject("result").get("key").getAsString();
		LOG.debug("Tapo's key is: " + keyFromTapo);
		LOG.debug("Our session cookie is: " + handshakeResponse.getCookie());

		LOG.info("Decoding key...");
		C658a c658a = KspEncryption.decodeTapoKey(keyFromTapo, kspKeyPair);
		if (c658a == null) {
			System.exit(1);
		}
		LOG.info("Decoded!");

		LOG.info("Logging in...");
		JsonObject resp = tapoFlow.loginRequest(email, password, c658a, handshakeResponse.getCookie());
		String token = resp.getAsJsonObject("result").get("token").getAsString();
		LOG.debug("Got token: " + token);

		tapoFlow.setPlugState(c658a, token, handshakeResponse.getCookie(), enabled);
	}
}
