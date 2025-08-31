package com.example.demo.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

	private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

	private final JavaMailSender mailSender;

	public EmailService(JavaMailSender mailSender) {
		this.mailSender = mailSender;
	}

	public void sendOTP(String toEmail, String otp) {
		try {
			SimpleMailMessage message = new SimpleMailMessage();
			message.setTo(toEmail);
			message.setSubject("OTP for login to AFS");
			message.setText(buildOTPEmailContent(otp));
			message.setFrom("noreply@example.com");

			mailSender.send(message);
			logger.info("OTP email sent successfully to: {}", toEmail);

		} catch (Exception e) {
			logger.error("Failed to send OTP email to: {}", toEmail, e);
			throw new RuntimeException("Failed to send OTP email", e);
		}
	}

	private String buildOTPEmailContent(String otp) {
		return String.format("""
				Dear User,

				Your One-Time Password (OTP) is: %s

				OTP is valid for 5 minutes"
				
				""", otp);
	}
}