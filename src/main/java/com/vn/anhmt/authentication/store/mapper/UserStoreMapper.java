package com.vn.anhmt.authentication.store.mapper;

import com.vn.anhmt.authentication.domain.User;
import com.vn.anhmt.authentication.entity.UserEntity;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class UserStoreMapper {

    public static User toUser(final UserEntity userEntity) {
        if (userEntity == null) {
            return null;
        }

        return User.builder()
                .username(userEntity.getUsername())
                .password(userEntity.getPassword())
                .id(userEntity.getId())
                .build();
    }
}
