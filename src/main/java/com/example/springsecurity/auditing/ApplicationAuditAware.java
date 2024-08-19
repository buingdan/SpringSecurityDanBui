package com.example.springsecurity.auditing;

import java.util.Optional;
import java.util.UUID;

import com.example.springsecurity.entity.User;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class ApplicationAuditAware implements AuditorAware<UUID> {
    //lấy ra thông tin của người dùng đang xác thực trên hệ thống
    @Override
    public Optional<UUID> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Nếu không có thông tin xác thực hoặc là xác thực ẩn danh
        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return Optional.empty();
        }

        // Chuyển đổi thông tin xác thực về đối tượng User
        User userPrincipal = (User) authentication.getPrincipal();

        // Trả về mã nhận dạng (ID) của người dùng
        return Optional.ofNullable(userPrincipal.getId());
    }
}
