package com.example.demo.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.demo.model.User;
import com.example.demo.repo.UserRepository;
import com.example.demo.service.EmailService;
import com.example.demo.service.OTPService;

import java.io.IOException;
import java.util.Optional;

@Component
public class Dual2FAFilter extends OncePerRequestFilter {

	private static final Logger logger = LoggerFactory.getLogger(Dual2FAFilter.class);

	private final UserRepository userRepository;
	private final OTPService otpService;
	private final EmailService emailService;

	public Dual2FAFilter(UserRepository userRepository, OTPService otpService, EmailService emailService) {
		this.userRepository = userRepository;
		this.otpService = otpService;
		this.emailService = emailService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String requestURI = request.getRequestURI();

		// Skip filter for login, 2fa, and static resources
		if (requestURI.contains("/login") || requestURI.contains("/2fa") || requestURI.contains("/css")
				|| requestURI.contains("/js") || requestURI.contains("/webjars")) {
			filterChain.doFilter(request, response);
			return;
		}

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		HttpSession session = request.getSession();

		if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {

			Boolean twoFactorVerified = (Boolean) session.getAttribute("2FA_VERIFIED");

			if (twoFactorVerified == null || !twoFactorVerified) {
				// Check which 2FA method is enabled for the user
				Optional<User> userOpt = userRepository.findByUsername(auth.getName());
				if (userOpt.isPresent()) {
					User user = userOpt.get();

					if (user.isEmailOtpEnabled()) {
						// Generate and send OTP if not already sent
						if (!otpService.isOTPValid(user.getUsername())) {
							String otp = otpService.generateOTP(user.getUsername());
							emailService.sendOTP(user.getEmail(), otp);
							logger.info("New OTP sent to user: {}", user.getUsername());
						}

						session.setAttribute("2FA_METHOD", "email");
						response.sendRedirect("/2fa/email");
						return;
					} else if (user.isTotpEnabled()) {
						session.setAttribute("2FA_METHOD", "totp");
						response.sendRedirect("/2fa/totp");
						return;
					}
				}
			}
		}

		filterChain.doFilter(request, response);
	}
}