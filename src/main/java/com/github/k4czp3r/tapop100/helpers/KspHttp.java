package com.github.k4czp3r.tapop100.helpers;


import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.inject.Nullable;

import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.Response;

public class KspHttp {
	public static final MediaType JSON
			= MediaType.parse("application/json; charset=utf-8");
	private static final Logger LOG = LoggerFactory.getLogger(KspHttp.class);
	private final OkHttpClient okHttpClient;

	public KspHttp() {
		this.okHttpClient = new OkHttpClient();
	}

	public Response makePost(String url, String json, @Nullable String cookie) throws IOException {
		RequestBody body = RequestBody.create(JSON, json);
		Request request = new Request.Builder()
				.addHeader("Cookie", cookie != null ? cookie : "")
				.url(url)
				.post(body)
				.build();
		boolean executed = false;
		Response response = null;
		while (!executed) {
			try {
				response = okHttpClient.newCall(request).execute();
				executed = true;
			} catch (IOException ex) {
				LOG.error("Request failed, retry...");
			}
		}
		return response;

	}
}
