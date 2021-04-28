package org.iptime.glegend.member.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class Auth {
    /**
     * CLIENT ID
     */
    @Pattern(regexp= "^[a-zA-Z0-9-_]{0,20}$", message="2011")
    String id ="";

    /**
     * CLIENT Password
     */
    @NotNull(message = "2013")
    String pwd = "";
}
