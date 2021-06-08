package com.bim999.iotpre.dao.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class User {
    public String id;
    public String username;
    public String name;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    public String password;
    public String phone;
    public String permitProjectId;
    public String role;

}
