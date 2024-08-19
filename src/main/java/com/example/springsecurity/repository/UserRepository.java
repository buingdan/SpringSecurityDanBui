package com.example.springsecurity.repository;

import com.example.springsecurity.entity.User;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends BaseRepository<User, UUID> {
    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);
}

