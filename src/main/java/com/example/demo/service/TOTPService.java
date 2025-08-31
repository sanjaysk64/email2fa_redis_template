package com.example.demo.service;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Service
public class TOTPService {

	private static final Logger logger = LoggerFactory.getLogger(TOTPService.class);

	@Value("${app.issuer-name:Dual2FAAuth}")
	private String issuerName;

	public String generateSecret() {
		return Base64.getEncoder().encodeToString(TimeBasedOneTimePasswordUtil.generateBase32Secret().getBytes());
	}

	public boolean verifyCode(String secret, String code) {
		try {
			String decodedSecret = new String(Base64.getDecoder().decode(secret));
			int otp = Integer.parseInt(code);

			long currentTimeMillis = System.currentTimeMillis();
			long step = TimeUnit.SECONDS.toMillis(30);

			// current step
			if (TimeBasedOneTimePasswordUtil.validateCurrentNumber(decodedSecret, otp, currentTimeMillis)) {
				return true;
			}
			// previous step (allow -30s drift)
			if (TimeBasedOneTimePasswordUtil.validateCurrentNumber(decodedSecret, otp, currentTimeMillis - step)) {
				return true;
			}
			// next step (allow +30s drift)
			if (TimeBasedOneTimePasswordUtil.validateCurrentNumber(decodedSecret, otp, currentTimeMillis + step)) {
				return true;
			}
			return false;
		} catch (GeneralSecurityException | NumberFormatException e) {
			logger.error("TOTP verification failed: {}", e.getMessage());
			return false;
		}
	}

	public String generateQRCodeUrl(String username, String secret) {
		String decodedSecret = new String(Base64.getDecoder().decode(secret));
		// width/height = 200px
		return TimeBasedOneTimePasswordUtil.qrImageUrl(username + "@" + issuerName, decodedSecret, 200);
	}

}