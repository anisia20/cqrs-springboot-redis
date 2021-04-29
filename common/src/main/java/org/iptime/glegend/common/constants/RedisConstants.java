package org.iptime.glegend.common.constants;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum RedisConstants {
    CQRS_H_CLIENT("CQRS_H_CLIENT", "클라이언트 정보"),
    CQRS_S_KEYGEN_SVRKEY_MEMBER("CQRS_S_KEYGEN_SVRKEY_MEMBER", "회원 서버키 ");
    public String key;
    public String desc;
}
