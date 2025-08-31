package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.demo.model.User;
import com.example.demo.repo.UserRepository;
import org.springframework.boot.CommandLineRunner;

@SpringBootApplication
public class Multiple2FaSetupApplication {

	public static void main(String[] args) {
		SpringApplication.run(Multiple2FaSetupApplication.class, args);
	}

	@Bean
	public CommandLineRunner initData(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		return args -> {
			if (userRepository.count() == 0) {
				User testUser = new User("testuser", passwordEncoder.encode("password123"), "test@example.com");
				User adminUser = new User("admin", passwordEncoder.encode("admin123"), "admin@example.com");

				userRepository.save(testUser);
				userRepository.save(adminUser);

				System.out.println("✅ Test users created:");
				System.out.println("   Username: testuser, Password: password123");
				System.out.println("   Username: admin, Password: admin123");
			}
		};
	}
}
