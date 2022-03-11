package com.createuserservice;

import com.createuserservice.models.User;
import com.createuserservice.payload.JwtResponse;
import com.createuserservice.payload.UserNotFoundException;
import com.createuserservice.repository.UserRepository;
import com.createuserservice.security.JwtUtils;
import com.createuserservice.security.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.transaction.Transactional;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import javax.mail.*;

@Service
public class AuthService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtUtils jwtUtils;

    private JavaMailSender mailSender;

    @Transactional
    public JwtResponse updateUserAuth(Long userId, String password){
        System.out.println("inside update Function");
        String jwt = generateToken(userId,password);
        System.out.println("Token Generated----" + jwt);
        Date modifiedDate = updateDate();
         userRepository.updateUserSaveToken(
                userId,
                modifiedDate,
                jwt
        );
         System.out.println("----------"+userId);
        JwtResponse jwtResponse = new JwtResponse(userId, jwt);
        return jwtResponse;
    }

    private String generateToken(Long userId, String password){
        System.out.println("inside generateToken Function--------"+userId +"---" + password);

        String username = String.valueOf(userId);
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));

        System.out.println("is Authorized" + authentication.isAuthenticated());

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        System.out.println(jwt + "jwt Token");
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        return jwt;
    }

    public Date updateDate(){
        Date updatedTime = new Date();
        return updatedTime;
    }

    public void updateResetPasswordToken(String token, String email) throws UserNotFoundException {
        User user = userRepository.findByEmail(email);
        if (user != null) {
            user.setResetPasswordToken(token);
            userRepository.save(user);
        } else {
            throw new UserNotFoundException("Could not find any customer with the email " + email);
        }
    }

    public User getByResetPasswordToken(String token) {
        return userRepository.findByResetPasswordToken(token);
    }

    public void updatePassword(User customer, String newPassword) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String encodedPassword = passwordEncoder.encode(newPassword);
        customer.setPassword(encodedPassword);

        customer.setResetPasswordToken(null);
        userRepository.save(customer);
    }

    @Transactional
    public void sendEmail(String recipientEmail, String link)
throws MessagingException, UnsupportedEncodingException {
MimeMessage message = mailSender.createMimeMessage();
MimeMessageHelper helper = new MimeMessageHelper(message);
String subject = "Here's the link to reset your password";
String content = "<p>Hello,</p>"
+ "<p>You have requested to reset your password.</p>"
+ "<p>Click the link below to change your password:</p>"
+ "<p><a href=\"" + link + "\">Change my password</a></p>"
+ "<br>"
+ "<p>Ignore this email if you do remember your password, "
+ "or you have not made the request.</p>";
helper.setFrom("contact@shopme.com", "Shopme Support");
helper.setTo(recipientEmail);
helper.setSubject(subject);

helper.setText(content, true);

mailSender.send(message);
}

}
