package com.bubaum.module.Model;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@Data
public class Message {
    private int status = 0 ;
	private String message = "OK";
	@JsonInclude(JsonInclude.Include.NON_NULL)
	private Object result;
}
