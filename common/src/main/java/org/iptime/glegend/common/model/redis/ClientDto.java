package org.iptime.glegend.common.model.redis;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.io.Serializable;

@Data
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class ClientDto implements Serializable {
    /** serialVersionUID. */
    private static final long serialVersionUID = 9014538167542847436L;

    /** 클라이언트 ID. */
    private String id;

    /** 클라이언트 PWD. */
    private String pwd;

    /** 클라이언트 PWD. */
    private String updatdt;
}
