package com.example.springsecurity.config;

import java.io.IOException;

import com.example.springsecurity.repository.TokenRepository;
import com.example.springsecurity.service.jwt.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        // Bỏ qua yêu cầu đến đường dẫn /api/v1/auth (đăng nhập, đăng ký, ...)
        if (request.getServletPath().contains("/api/v1/auth")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader("Authorization"); // Lấy ra header từ request
        final String jwt;
        final String userEmail;

        // Kiểm tra định dạng token trên header xem header có null hoặc bắt đầu bằng chuỗi Bearer không
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Nếu header tồn tại và đúng định dạng sẽ bỏ qua 7 ký tự đầu tiên
        jwt = authHeader.substring(7); // Cắt chuỗi header từ ký tự index số 7 trở đi ( "Bearer " )
        userEmail = jwtService.extractUsername(jwt); // Lấy ra userEmail từ token

        // Kiểm tra chuỗi vừa lấy ra có bị null hoặc trong ContextHolder có bị null
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            var isTokenValid = tokenRepository
                    .findByAccessToken(jwt) // Tìm token trong database theo chuỗi jwt
                    .map(t -> !t.getIsExpired() && !t.getIsRevoked())
                    .orElse(false);

            // Kiểm tra xem token có hợp lệ không, nếu hợp lệ lưu vào ContextHolder
            if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }

    protected void doFilterInternal1(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        // Bỏ qua yêu cầu đến đường dẫn /api/v1/auth (đăng nhập, đăng ký, ...)
        if (request.getServletPath().contains("/api/v1/auth")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader("Authorization"); // Lấy ra header từ request
        final String jwt;
        final String userEmail;

        // Kiểm tra xem header có null hoặc bắt đầu bằng chuỗi Bearer không
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Nếu header tồn tại và đúng định dạng sẽ bỏ qua 7 ký tự đầu tiên
        jwt = authHeader.substring(7); // Cắt chuỗi header từ ký tự index số 7 trở đi ( "Bearer " )
        userEmail = jwtService.extractUsername(jwt); // Lấy ra userEmail từ token

        // Kiểm tra chuỗi vừa lấy ra có bị null hoặc trong ContextHolder có bị null
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            var isTokenValid = tokenRepository
                    .findByAccessToken(jwt) // Tìm token trong database theo chuỗi jwt
                    .map(t -> !t.getIsExpired() && !t.getIsRevoked())
                    .orElse(false);

            // Kiểm tra xem token có hợp lệ không, nếu hợp lệ lưu vào ContextHolder
            if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
