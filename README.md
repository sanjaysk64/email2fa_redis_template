package com.example.demo.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;

@Service
public class OtpServices {

	private static final Logger logger = LoggerFactory.getLogger(OtpServices.class);
	private static final String OTP_PREFIX = "otp:";
	private static final String RATE_LIMIT_PREFIX = "rate_limit:";

	@Value("${app.otp.length:6}")
	private int otpLength;

	@Value("${app.otp.expiry-minutes:5}")
	private int otpExpiryMinutes;

	@Value("${app.otp.rate-limit.max-requests:3}")
	private int maxOtpRequests;

	@Value("${app.otp.rate-limit.window-minutes:5}")
	private int rateLimitWindowMinutes;

	private final RedisTemplate<String, String> redisTemplate;
	private final SecureRandom secureRandom = new SecureRandom();

	public OtpServices(RedisTemplate<String, String> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}

	/**
	 * Generate OTP with rate limiting and store in Redis with expiry.
	 */
	public String generateOTP(String username) {
		// Check rate limit first
		if (!isWithinRateLimit(username)) {
			logger.warn("Rate limit exceeded for user: {}", username);
			throw new RuntimeException("Rate limit exceeded. Please try again later.");
		}

		String otp = String.format("%0" + otpLength + "d", secureRandom.nextInt((int) Math.pow(10, otpLength)));
		String key = OTP_PREFIX + username;

		redisTemplate.opsForValue().set(key, otp, Duration.ofMinutes(otpExpiryMinutes));

		// Increment rate limit counter
		incrementRateLimitCounter(username);

		logger.info("OTP generated for user: {} (expires in {} minutes)", username, otpExpiryMinutes);
		return otp;
	}

	/**
	 * Verify OTP using atomic GETDEL (avoids race conditions).
	 */
	public boolean verifyOTP(String username, String providedOTP) {
		String key = OTP_PREFIX + username;

		// Use explicit RedisCallback type to avoid ambiguity
		String storedOTP = redisTemplate.execute(new RedisCallback<String>() {
			@Override
			public String doInRedis(org.springframework.data.redis.connection.RedisConnection connection) {
				byte[] value = connection.stringCommands().getDel(key.getBytes(StandardCharsets.UTF_8));
				return value != null ? new String(value, StandardCharsets.UTF_8) : null;
			}
		});

		if (storedOTP != null && storedOTP.equals(providedOTP)) {
			logger.info("OTP verified and deleted for user: {}", username);
			return true;
		}

		logger.warn("OTP verification failed for user: {}", username);
		return false;
	}

	/**
	 * Check if an OTP exists for the user.
	 */
	public boolean isOTPValid(String username) {
		String key = OTP_PREFIX + username;

		Boolean exists = redisTemplate.execute(new RedisCallback<Boolean>() {
			@Override
			public Boolean doInRedis(org.springframework.data.redis.connection.RedisConnection connection) {
				return connection.keyCommands().exists(key.getBytes(StandardCharsets.UTF_8));
			}
		});

		return Boolean.TRUE.equals(exists);
	}

	/**
	 * Get remaining TTL of OTP in seconds.
	 */
	public long getOTPRemainingTime(String username) {
		String key = OTP_PREFIX + username;

		Long expire = redisTemplate.execute(new RedisCallback<Long>() {
			@Override
			public Long doInRedis(org.springframework.data.redis.connection.RedisConnection connection) {
				return connection.keyCommands().ttl(key.getBytes(StandardCharsets.UTF_8));
			}
		});

		// Redis TTL returns:
		// -1 if key exists but has no expiry
		// -2 if key does not exist
		return (expire != null && expire > 0) ? expire : 0;
	}

	/**
	 * Manually delete OTP.
	 */
	public void deleteOTP(String username) {
		String key = OTP_PREFIX + username;

		redisTemplate.execute(new RedisCallback<Void>() {
			@Override
			public Void doInRedis(org.springframework.data.redis.connection.RedisConnection connection) {
				connection.keyCommands().del(key.getBytes(StandardCharsets.UTF_8));
				return null;
			}
		});

		logger.info("OTP manually deleted for user: {}", username);
	}

	/**
	 * Check if user is within rate limit for OTP requests.
	 */
	private boolean isWithinRateLimit(String username) {
		String rateLimitKey = RATE_LIMIT_PREFIX + username;

		String currentCount = redisTemplate.opsForValue().get(rateLimitKey);
		int count = (currentCount != null) ? Integer.parseInt(currentCount) : 0;

		return count < maxOtpRequests;
	}

	/**
	 * Increment rate limit counter with sliding window expiry.
	 */
	private void incrementRateLimitCounter(String username) {
		String rateLimitKey = RATE_LIMIT_PREFIX + username;

		redisTemplate.execute(new RedisCallback<Void>() {
			@Override
			public Void doInRedis(org.springframework.data.redis.connection.RedisConnection connection) {
				byte[] keyBytes = rateLimitKey.getBytes(StandardCharsets.UTF_8);

				// Increment the counter
				Long newCount = connection.stringCommands().incr(keyBytes);

				// Set expiry only on first increment (when count becomes 1)
				if (newCount != null && newCount == 1) {
					connection.keyCommands().expire(keyBytes, Duration.ofMinutes(rateLimitWindowMinutes).getSeconds());
				}

				return null;
			}
		});
	}

	/**
	 * Get remaining rate limit attempts for user.
	 */
	public int getRemainingAttempts(String username) {
		String rateLimitKey = RATE_LIMIT_PREFIX + username;
		String currentCount = redisTemplate.opsForValue().get(rateLimitKey);
		int count = (currentCount != null) ? Integer.parseInt(currentCount) : 0;
		return Math.max(0, maxOtpRequests - count);
	}

	/**
	 * Get remaining time until rate limit resets (in seconds).
	 */
	public long getRateLimitResetTime(String username) {
		String rateLimitKey = RATE_LIMIT_PREFIX + username;

		Long expire = redisTemplate.execute(new RedisCallback<Long>() {
			@Override
			public Long doInRedis(org.springframework.data.redis.connection.RedisConnection connection) {
				return connection.keyCommands().ttl(rateLimitKey.getBytes(StandardCharsets.UTF_8));
			}
		});

		return (expire != null && expire > 0) ? expire : 0;
	}

	/**
	 * Reset rate limit for a user (admin function).
	 */
	public void resetRateLimit(String username) {
		String rateLimitKey = RATE_LIMIT_PREFIX + username;
		redisTemplate.delete(rateLimitKey);
		logger.info("Rate limit reset for user: {}", username);
	}

	/**
	 * Get current rate limit status for user.
	 */
	public RateLimitStatus getRateLimitStatus(String username) {
		String rateLimitKey = RATE_LIMIT_PREFIX + username;
		String currentCount = redisTemplate.opsForValue().get(rateLimitKey);
		int count = (currentCount != null) ? Integer.parseInt(currentCount) : 0;

		long resetTime = getRateLimitResetTime(username);
		int remainingAttempts = Math.max(0, maxOtpRequests - count);
		boolean isLimited = count >= maxOtpRequests;

		return new RateLimitStatus(count, remainingAttempts, resetTime, isLimited);
	}

	/**
	 * Inner class to hold rate limit status information.
	 */
	public static class RateLimitStatus {
		private final int currentAttempts;
		private final int remainingAttempts;
		private final long resetTimeSeconds;
		private final boolean isLimited;

		public RateLimitStatus(int currentAttempts, int remainingAttempts, long resetTimeSeconds, boolean isLimited) {
			this.currentAttempts = currentAttempts;
			this.remainingAttempts = remainingAttempts;
			this.resetTimeSeconds = resetTimeSeconds;
			this.isLimited = isLimited;
		}

		public int getCurrentAttempts() {
			return currentAttempts;
		}

		public int getRemainingAttempts() {
			return remainingAttempts;
		}

		public long getResetTimeSeconds() {
			return resetTimeSeconds;
		}

		public boolean isLimited() {
			return isLimited;
		}

		@Override
		public String toString() {
			return String.format("RateLimitStatus{current=%d, remaining=%d, resetIn=%ds, limited=%s}", currentAttempts,
					remainingAttempts, resetTimeSeconds, isLimited);
		}
	}
}
