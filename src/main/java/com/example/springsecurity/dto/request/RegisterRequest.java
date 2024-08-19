package com.example.springsecurity.dto.request;

import com.example.springsecurity.constant.Role;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Setter
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class RegisterRequest {
    String fullName;
    String username;
    String password;
    Role role;
}