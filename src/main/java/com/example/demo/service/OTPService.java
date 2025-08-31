package com.example.demo.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import java.security.SecureRandom;
import java.time.Duration;

@Service
public class OTPService {

	private static final Logger logger = LoggerFactory.getLogger(OTPService.class);
	private static final String OTP_PREFIX = "otp:";

	@Value("${app.otp.length:6}")
	private int otpLength;

	@Value("${app.otp.expiry-minutes:5}")
	private int otpExpiryMinutes;

	private final RedisTemplate<String, String> redisTemplate;
	private final SecureRandom secureRandom = new SecureRandom();

	public OTPService(RedisTemplate<String, String> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}

	public String generateOTP(String username) {
		String otp = String.format("%0" + otpLength + "d", secureRandom.nextInt((int) Math.pow(10, otpLength)));
		String key = OTP_PREFIX + username;

		redisTemplate.opsForValue().set(key, otp, Duration.ofMinutes(otpExpiryMinutes));

		logger.info("OTP generated for user: {} (expires in {} minutes)", username, otpExpiryMinutes);
		return otp;
	}

	public boolean verifyOTP(String username, String providedOTP) {
		String key = OTP_PREFIX + username;
		String storedOTP = redisTemplate.opsForValue().get(key);

		if (storedOTP != null && storedOTP.equals(providedOTP)) {
			redisTemplate.delete(key);
			logger.info("OTP verified and deleted for user: {}", username);
			return true;
		}

		logger.warn("OTP verification failed for user: {}", username);
		return false;
	}

	public boolean isOTPValid(String username) {
		String key = OTP_PREFIX + username;
		return Boolean.TRUE.equals(redisTemplate.hasKey(key));
	}

	public long getOTPRemainingTime(String username) {
		String key = OTP_PREFIX + username;
		Long expire = redisTemplate.getExpire(key);
		return expire != null ? expire : 0;
	}

	public void deleteOTP(String username) {
		String key = OTP_PREFIX + username;
		redisTemplate.delete(key);
		logger.info("OTP manually deleted for user: {}", username);
	}
}