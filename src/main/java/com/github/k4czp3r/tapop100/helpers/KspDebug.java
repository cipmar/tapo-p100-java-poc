package com.github.k4czp3r.tapop100.helpers;

import java.util.Date;

public class KspDebug {

	public static void out(String content) {
		System.out.printf("[TAPO-PoC] %1$tF %1tT %s%n", new Date(), content);
	}
}
