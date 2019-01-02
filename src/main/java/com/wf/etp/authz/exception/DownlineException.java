package com.wf.etp.authz.exception;

public class DownlineException extends EtpException {

    private static final long serialVersionUID = -5163940850688796162L;

    public DownlineException() {
        super(402, "token被迫下线通知");
    }

    public DownlineException(String message) {
        super(402, message);
    }

}
