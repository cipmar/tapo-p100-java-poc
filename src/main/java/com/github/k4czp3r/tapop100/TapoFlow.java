package com.github.k4czp3r.tapop100;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.k4czp3r.tapop100.domain.Handshake;
import com.github.k4czp3r.tapop100.domain.HandshakeParams;
import com.github.k4czp3r.tapop100.domain.HandshakeResponse;
import com.github.k4czp3r.tapop100.domain.KspKeyPair;
import com.github.k4czp3r.tapop100.domain.ParamsBean;
import com.github.k4czp3r.tapop100.domain.SecurePassthrough;
import com.github.k4czp3r.tapop100.helpers.KspB64;
import com.github.k4czp3r.tapop100.helpers.KspHttp;
import com.github.k4czp3r.tapop100.helpers.KspJson;
import com.google.gson.JsonObject;
import com.squareup.okhttp.Response;

public class TapoFlow {

	private static final Logger LOG = LoggerFactory.getLogger(TapoFlow.class);
	private final KspHttp kspHttp;

	private final String address;

	public TapoFlow(String address) {
		this.kspHttp = new KspHttp();
		this.address = address;

	}


	public HandshakeResponse makeHandshake(KspKeyPair kspKeyPair) {
		HandshakeParams handshakeParams = new HandshakeParams();
		handshakeParams.setKey(kspKeyPair.getPublicKey());

		Handshake handshake = new Handshake(handshakeParams);


		try {
			Response response = this.kspHttp.makePost(String.format("http://%s/app", address), KspJson.convertToString(handshake), null);
			String responseBody = response.body().string();
			String cookie = response.header("Set-Cookie").split(";")[0];
			LOG.debug("Server responded with: " + responseBody);
			return new HandshakeResponse(
					cookie,
					KspJson.convertToObj(responseBody)
			);
		} catch (IOException ex) {
			LOG.error("Something went wrong: " + ex.getMessage());
			return null;
		}
	}

	public void setPlugState(C658a c658a, String token, String cookie, boolean on) {
		try {
			DeviceInfoParams deviceInfoParams = new DeviceInfoParams();
			deviceInfoParams.setDeviceOn(on);

			TPIoTRequest<DeviceInfoParams> tpIoTRequest = new TPIoTRequest<>();
			tpIoTRequest.setMethod("set_device_info");
			tpIoTRequest.setParams(deviceInfoParams);
			tpIoTRequest.setRequestTimeMils(System.currentTimeMillis());
			tpIoTRequest.setTerminalUUID("88-54-DE-AD-52-E1");

			LOG.debug(KspJson.convertToString(tpIoTRequest));

			String encrypted = c658a.mo38009b_enc(KspJson.convertToString(tpIoTRequest));
			ParamsBean paramsBean = new ParamsBean(encrypted);
			SecurePassthrough securePassthrough = new SecurePassthrough(paramsBean);
			String requestBody = KspJson.convertToString(securePassthrough);

			Response response = this.kspHttp.makePost(String.format("http://%s/app?token=%s", address, token), requestBody, cookie);
			String respBody = response.body().string();

			JsonObject jsonObject = KspJson.convertToObj(respBody);
			String encryptedResponse = jsonObject.getAsJsonObject("result").get("response").getAsString();
			String dec = c658a.mo38006a_dec(encryptedResponse);

			LOG.debug("Server response: " + respBody);
			LOG.debug("Decrypted: " + dec);

			LOG.info("Plug state set successfully to {}!\n", on);
		} catch (Exception ex) {
			LOG.error("Something went wrong! " + ex.getMessage());
		}
	}

	public void changeStatusLed(C658a c658a, String token, String cookie, boolean enabled) {
		try {
			PlugDeviceInfoParams plugDeviceInfoParams = new PlugDeviceInfoParams();
			plugDeviceInfoParams.setLedEnable(enabled);

			TPIoTRequest<PlugDeviceInfoParams> tpIoTRequest = new TPIoTRequest<>();
			tpIoTRequest.setMethod("set_led_status");
			tpIoTRequest.setParams(plugDeviceInfoParams);

			LOG.debug(KspJson.convertToString(tpIoTRequest));

			String encrypted = c658a.mo38009b_enc(KspJson.convertToString(tpIoTRequest));
			ParamsBean paramsBean = new ParamsBean(encrypted);
			SecurePassthrough securePassthrough = new SecurePassthrough(paramsBean);
			String requestBody = KspJson.convertToString(securePassthrough);

			Response response = this.kspHttp.makePost(String.format("http://%s/app?token=%s", address, token), requestBody, cookie);
			String respBody = response.body().string();

			JsonObject jsonObject = KspJson.convertToObj(respBody);
			String encryptedResponse = jsonObject.getAsJsonObject("result").get("response").getAsString();
			String dec = c658a.mo38006a_dec(encryptedResponse);
			LOG.debug(dec);
			LOG.debug("Server response: " + response.body().string());


		} catch (Exception ex) {
			LOG.error("Something went wrong! " + ex.getMessage());

		}
	}

	public JsonObject loginRequest(String username, String password, C658a c658a, String cookie) {
		try {
			LoginDeviceRequest loginDeviceRequest = new LoginDeviceRequest();
			loginDeviceRequest.setUsername(KspB64.encodeToString(KspEncryption.shaDigestUsername(username).getBytes()));
			loginDeviceRequest.setPassword(KspB64.encodeToString(password.getBytes()));

			TPIoTRequest<LoginDeviceRequest> tpIoTRequest = new TPIoTRequest<>();
			tpIoTRequest.setMethod("login_device");
			tpIoTRequest.setParams(loginDeviceRequest);
			tpIoTRequest.setRequestTimeMils(0);

			String getMe = KspJson.convertToString(tpIoTRequest);
			LOG.debug("Unencrypted request content: " + KspJson.convertToString(tpIoTRequest));
			LOG.debug("Encrypting request content...");
			String encrypted = c658a.mo38009b_enc(KspJson.convertToString(tpIoTRequest));

			ParamsBean paramsBean = new ParamsBean(encrypted);

			SecurePassthrough securePassthrough = new SecurePassthrough(paramsBean);

			String requestBody = KspJson.convertToString(securePassthrough);
			LOG.debug("request Body " + requestBody);

			Response response = this.kspHttp.makePost(String.format("http://%s/app", address), requestBody, cookie);
			String resp = response.body().string();
			LOG.debug("Server responsed with (encrypted): " + resp);

			JsonObject jsonResponse = KspJson.convertToObj(resp);
			String encryptedResponse = jsonResponse.getAsJsonObject("result").get("response").getAsString();
			String decryptedResponse = c658a.mo38006a_dec(encryptedResponse);
			LOG.debug("Decrypted response: " + decryptedResponse);
			return KspJson.convertToObj(decryptedResponse);

		} catch (Exception ex) {
			LOG.error("Something went wrong: " + ex.getMessage());
			return null;
		}
	}

}
