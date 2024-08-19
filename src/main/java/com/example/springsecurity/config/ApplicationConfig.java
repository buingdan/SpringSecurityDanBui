package com.example.springsecurity.config;
import java.util.UUID;

import com.example.springsecurity.auditing.ApplicationAuditAware;
import com.example.springsecurity.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    private final UserRepository repository;

    @Bean
    public UserDetailsService userDetailsService() {//lấy thông tin từ db
        return username -> (UserDetails)
                repository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
    @Bean
    public AuthenticationProvider authenticationProvider() {//thực hiện xác thực thông tin của user
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
    @Bean
    public AuditorAware<UUID> auditorAware() {
        return new ApplicationAuditAware();
    }//định nghĩa hàm lấy thông tin user cho ApplicationAuditAware.java
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {//quản lý xác thực
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {//mã hóa mật khẩu
        return new BCryptPasswordEncoder();
    }
}

