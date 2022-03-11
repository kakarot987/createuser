package com.createuserservice.security;

import com.createuserservice.models.User;
import com.createuserservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.stream.Stream;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
	@Autowired
	UserRepository userRepository;

	@Override
	@Transactional
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUserId(Long.valueOf(username))
				.orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
		return UserDetailsImpl.build(user);
	}
	
	public Stream<User> getUser(){
		return userRepository.findAll().stream();
	}

}