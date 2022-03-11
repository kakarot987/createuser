package com.createuserservice;

import com.createuserservice.models.User;
import com.createuserservice.payload.*;
import com.createuserservice.repository.UserRepository;
import com.createuserservice.security.UserDetailsServiceImpl;
import net.bytebuddy.utility.RandomString;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.UnsupportedEncodingException;
import java.text.SimpleDateFormat;
import java.util.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

	@Autowired
	UserRepository userRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	AuthService authService;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		if (loginRequest.getEmail() == null) {
			Optional<User> user = userRepository.findByPhoneNumber(loginRequest.getPhoneNumber());
			JwtResponse jwtResponse = authService.updateUserAuth(user.get().getUserId(),
					loginRequest.getPassword());
			return ResponseEntity.ok(jwtResponse);
		}
		if (loginRequest.getPhoneNumber() == null) {
			System.out.println("very through email");
			User user = userRepository.findByEmail(loginRequest.getEmail());
			JwtResponse jwtResponse = authService.updateUserAuth(user.getUserId(),
					loginRequest.getPassword());
			return ResponseEntity.ok(jwtResponse);
		}
		return ResponseEntity.badRequest().body("Email or Phone is not correct");
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		System.out.println("-------" + signUpRequest.getPassword() + "---" +
				signUpRequest.getUserId());

		String username = String.valueOf(signUpRequest.getUserId());

		System.out.println(username);
		//return if userId is already registered
		if (userRepository.existsByUserId(signUpRequest.getUserId())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: userId is already in use!"));
		}
		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already in use!"));
		}
		if (userRepository.existsByPhoneNumber(signUpRequest.getPhoneNumber())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Phone Number is already in use!"));
		}

		System.out.println("Authorizing userId and password");

		//Setup Registration Date
		Date createdDate = new Date();
		SimpleDateFormat formatter = new SimpleDateFormat("dd-MM-yyyy");

		// Create new user's account
		User user = new User(signUpRequest.getUserId(),
				signUpRequest.getEmail(),
				signUpRequest.getPhoneNumber(),
				"jwt",
				encoder.encode(signUpRequest.getPassword()),
				createdDate);
		userRepository.save(user);
		return ResponseEntity.ok("User Register Successfully");
	}

	@PostMapping("/forgot_password")
	public String processForgotPassword(HttpServletRequest request, Model model) {
		String email = request.getParameter("email");
		String token = RandomString.make(30);
		try {
			authService.updateResetPasswordToken(token, email);
			String resetPasswordLink = Utility.getSiteURL(request) + "/reset_password?token=" + token;
			authService.sendEmail(email, resetPasswordLink);
			model.addAttribute("message", "We have sent a reset password link to your email. Please check.");

		} catch (UserNotFoundException ex) {
			model.addAttribute("error", ex.getMessage());
		} catch (UnsupportedEncodingException | MessagingException e) {
			model.addAttribute("error", "Error while sending email");
		}

		return "forgot_password_form";
	}

	@PostMapping("/reset_password")
	public String processResetPassword(HttpServletRequest request, Model model) {
		String token = request.getParameter("token");
		String password = request.getParameter("password");

		User customer = authService.getByResetPasswordToken(token);
		model.addAttribute("title", "Reset your password");

		if (customer == null) {
			model.addAttribute("message", "Invalid Token");
			return "message";
		} else {
			authService.updatePassword(customer, password);

			model.addAttribute("message", "You have successfully changed your password.");
		}

		return "message";
	}
}
