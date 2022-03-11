package com.createuserservice.models;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.Date;

@Entity
@Table(	name = "userAuth",
		uniqueConstraints = { 
			@UniqueConstraint(columnNames = "userId")
		})
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "userAuthId")
	private Long id;

	@Column(name = "userId")
	private Long userId;

	@NotBlank
	@Size(max = 50)
	@Email
	private String email;

	@Column(name = "phoneNumber")
	private Long phoneNumber;

	@Column(name = "authToken")
	@Size(max = 200)
	private String authToken;

	@Size(max = 120)
	private String password;

	@Column(name = "reset_password_token")
	private String resetPasswordToken;

	private Date created;

	private Date modified;

	public User() {
	}

	public User(Long userId, String email, Long phoneNumber, String authToken, String password, Date created) {
		this.userId = userId;
		this.email = email;
		this.phoneNumber = phoneNumber;
		this.authToken = authToken;
		this.password = password;
		this.created = created;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public Long getPhoneNumber() {
		return phoneNumber;
	}

	public void setPhoneNumber(Long phoneNumber) {
		this.phoneNumber = phoneNumber;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Date getCreated() {
		return created;
	}

	public void setCreated(Date created) {
		this.created = created;
	}

	public Date getModified() {
		return modified;
	}

	public void setModified(Date modified) {
		this.modified = modified;
	}

	public String getAuthToken() {
		return authToken;
	}

	public void setAuthToken(String authToken) {
		this.authToken = authToken;
	}

	public Long getUserId() {
		return userId;
	}

	public void setUserId(Long userId) {
		this.userId = userId;
	}

	public String getResetPasswordToken() {
		return resetPasswordToken;
	}

	public void setResetPasswordToken(String resetPasswordToken) {
		this.resetPasswordToken = resetPasswordToken;
	}
}
