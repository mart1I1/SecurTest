package com.example.test.svc;

import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
public class CustomUserDetails implements UserDetailsService {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        val userDetails = new CustomUser(
                "test_username",
                passwordEncoder.encode("test_pwd"),
                true,
                true,
                true,
                true,
                Arrays.asList(new SimpleGrantedAuthority("AUTH_1"), new SimpleGrantedAuthority("AUTH_2")),
                "test_email",
                "test_phone"
                );

        return userDetails;
    }
}
