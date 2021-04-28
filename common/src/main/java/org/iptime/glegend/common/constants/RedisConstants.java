package org.iptime.glegend.common.constants;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum RedisConstants {
    CQRS_H_CLIENT("CQRS_H_CLIENT", "클라이언트 정보");
    public String key;
    public String desc;
}
