package com.wf.etp.authz.exception;

/**
 * token过期异常
 * 
 * @author wangfan
 * @date 2018-1-23 上午11:26:01
 */
public class ExpiredTokenException extends EtpException {
	private static final long serialVersionUID = -8019541050781876369L;

	public ExpiredTokenException() {
		super(401, "登录已过期");
	}
}
