package com.example.demo.controller;

import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.demo.model.User;
import com.example.demo.repo.UserRepository;
import com.example.demo.service.EmailService;
import com.example.demo.service.OTPService;
import com.example.demo.service.TOTPService;

import java.util.Optional;

@Controller
public class TwoFAController {

	private static final Logger logger = LoggerFactory.getLogger(TwoFAController.class);

	private final OTPService otpService;
	private final TOTPService totpService;
	private final EmailService emailService;
	private final UserRepository userRepository;

	public TwoFAController(OTPService otpService, TOTPService totpService, EmailService emailService,
			UserRepository userRepository) {
		this.otpService = otpService;
		this.totpService = totpService;
		this.emailService = emailService;
		this.userRepository = userRepository;
	}

	@GetMapping("/2fa/select")
	public String select2FAMethod(Authentication auth, HttpSession session, Model model) {
		if (auth == null || !auth.isAuthenticated()) {
			return "redirect:/login";
		}

		Optional<User> userOpt = userRepository.findByUsername(auth.getName());
		if (userOpt.isPresent()) {
			User user = userOpt.get();
			model.addAttribute("emailOtpEnabled", user.isEmailOtpEnabled());
			model.addAttribute("totpEnabled", user.isTotpEnabled());
		}

		return "2fa-select";
	}

	@PostMapping("/2fa/select")
	public String process2FASelection(@RequestParam String method, Authentication auth, HttpSession session,
			RedirectAttributes redirectAttributes) {
		if (auth == null || !auth.isAuthenticated()) {
			return "redirect:/login";
		}

		session.setAttribute("2FA_METHOD", method);

		if ("email".equals(method)) {
			Optional<User> userOpt = userRepository.findByUsername(auth.getName());
			if (userOpt.isPresent()) {
				User user = userOpt.get();

				// Generate and send OTP
				otpService.deleteOTP(user.getUsername());
				String otp = otpService.generateOTP(user.getUsername());
				emailService.sendOTP("mailmrsanjay64@gmail.com", otp);

				redirectAttributes.addFlashAttribute("success", "OTP sent to your email!");
				logger.info("OTP sent to user: {}", user.getUsername());
			}
			return "redirect:/2fa/email";
		} else if ("totp".equals(method)) {
			return "redirect:/2fa/totp";
		}

		return "redirect:/2fa/select";
	}

	@GetMapping("/2fa/email")
	public String email2FAPage(Authentication auth, Model model) {
		if (auth == null || !auth.isAuthenticated()) {
			return "redirect:/login";
		}

		Optional<User> userOpt = userRepository.findByUsername(auth.getName());
		if (userOpt.isPresent()) {
			User user = userOpt.get();
			model.addAttribute("email", maskEmail(user.getEmail()));
			model.addAttribute("username", user.getUsername());

			if (otpService.isOTPValid(user.getUsername())) {
				long remainingTime = otpService.getOTPRemainingTime(user.getUsername());
				model.addAttribute("remainingTime", remainingTime);
			} else {
				// Generate new OTP if expired
				String otp = otpService.generateOTP(user.getUsername());
				emailService.sendOTP("mailmrsanjay64@gmail.com", otp);
				model.addAttribute("newOtpSent", true);
				logger.info("New OTP generated and sent for user: {}", user.getUsername());
			}
		}

		return "2fa-email";
	}

	@PostMapping("/2fa/email/verify")
	public String verifyEmailOtp(@RequestParam String otp, Authentication auth, HttpSession session,
			RedirectAttributes redirectAttributes) {
		if (auth == null || !auth.isAuthenticated()) {
			return "redirect:/login";
		}

		if (otpService.verifyOTP(auth.getName(), otp)) {
			session.setAttribute("2FA_VERIFIED", true);
			logger.info("Email OTP verified successfully for user: {}", auth.getName());
			return "redirect:/home";
		} else {
			redirectAttributes.addFlashAttribute("error", "Invalid or expired OTP. Please try again.");
			logger.warn("Email OTP verification failed for user: {}", auth.getName());
			return "redirect:/2fa/email";
		}
	}

	@PostMapping("/2fa/email/resend")
	public String resendEmailOtp(Authentication auth, RedirectAttributes redirectAttributes) {
		if (auth == null || !auth.isAuthenticated()) {
			return "redirect:/login";
		}

		Optional<User> userOpt = userRepository.findByUsername(auth.getName());
		if (userOpt.isPresent()) {
			User user = userOpt.get();

			// Delete existing OTP and generate new one
			otpService.deleteOTP(user.getUsername());
			String otp = otpService.generateOTP(user.getUsername());
			emailService.sendOTP("mailmrsanjay64@gmail.com", otp);

			redirectAttributes.addFlashAttribute("success", "New OTP sent to your email!");
			logger.info("OTP resent for user: {}", user.getUsername());
		}

		return "redirect:/2fa/email";
	}

	@GetMapping("/2fa/totp")
	public String totp2FAPage(Authentication auth, Model model) {
		if (auth == null || !auth.isAuthenticated()) {
			return "redirect:/login";
		}

		return "2fa-totp";
	}

	@PostMapping("/2fa/totp/verify")
	public String verifyTotp(@RequestParam String code, Authentication auth, HttpSession session,
			RedirectAttributes redirectAttributes) {
		if (auth == null || !auth.isAuthenticated()) {
			return "redirect:/login";
		}

		Optional<User> userOpt = userRepository.findByUsername(auth.getName());
		if (userOpt.isPresent()) {
			User user = userOpt.get();

			if (totpService.verifyCode(user.getTotpSecret(), code)) {
				session.setAttribute("2FA_VERIFIED", true);
				logger.info("TOTP verified successfully for user: {}", auth.getName());
				return "redirect:/home";
			} else {
				redirectAttributes.addFlashAttribute("error", "Invalid TOTP code. Please try again.");
				logger.warn("TOTP verification failed for user: {}", auth.getName());
			}
		}

		return "redirect:/2fa/totp";
	}

	@GetMapping("/2fa/setup")
	public String setup2FAPage(Authentication auth, Model model) {
		if (auth == null || !auth.isAuthenticated()) {
			return "redirect:/login";
		}

		Optional<User> userOpt = userRepository.findByUsername(auth.getName());
		if (userOpt.isPresent()) {
			User user = userOpt.get();
			model.addAttribute("emailOtpEnabled", user.isEmailOtpEnabled());
			model.addAttribute("totpEnabled", user.isTotpEnabled());

			if (!user.isTotpEnabled() && user.getTotpSecret() == null) {
				String secret = totpService.generateSecret();
				user.setTotpSecret(secret);
				userRepository.save(user);

				String qrCodeUrl = totpService.generateQRCodeUrl(user.getUsername(), secret);
				model.addAttribute("qrCodeUrl", qrCodeUrl);
				model.addAttribute("secret", secret);
			} else if (user.isTotpEnabled()) {
				String qrCodeUrl = totpService.generateQRCodeUrl(user.getUsername(), user.getTotpSecret());
				model.addAttribute("qrCodeUrl", qrCodeUrl);
				model.addAttribute("secret", user.getTotpSecret());
			}
		}

		return "2fa-setup";
	}

	@PostMapping("/2fa/setup/email")
	public String enableEmail2FA(Authentication auth, RedirectAttributes redirectAttributes) {
		if (auth == null || !auth.isAuthenticated()) {
			return "redirect:/login";
		}

		Optional<User> userOpt = userRepository.findByUsername(auth.getName());
		if (userOpt.isPresent()) {
			User user = userOpt.get();
			user.setEmailOtpEnabled(true);
			user.setTotpEnabled(false);
			userRepository.save(user);

			redirectAttributes.addFlashAttribute("success", "Email OTP authentication enabled!");
			logger.info("Email OTP enabled for user: {}", user.getUsername());
		}

		return "redirect:/2fa/setup";
	}

	@PostMapping("/2fa/setup/totp")
	public String enableTotp2FA(Authentication auth, RedirectAttributes redirectAttributes) {
		if (auth == null || !auth.isAuthenticated()) {
			return "redirect:/login";
		}

		Optional<User> userOpt = userRepository.findByUsername(auth.getName());
		if (userOpt.isPresent()) {
			User user = userOpt.get();
			user.setEmailOtpEnabled(false);
			user.setTotpEnabled(true);
			userRepository.save(user);

			redirectAttributes.addFlashAttribute("success", "TOTP authentication enabled!");
			logger.info("TOTP enabled for user: {}", user.getUsername());
		}

		return "redirect:/2fa/setup";
	}

	private String maskEmail(String email) {
		if (email == null || email.length() < 3) {
			return email;
		}
		int atIndex = email.indexOf('@');
		if (atIndex <= 1) {
			return email;
		}
		return email.charAt(0) + "***" + email.substring(atIndex);
	}
}