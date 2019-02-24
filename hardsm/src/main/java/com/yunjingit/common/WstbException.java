package com.yunjingit.common;

public class WstbException extends RuntimeException {
    private String msg;

    @Override
    public String toString() {
        return "WstbException{" +
                "msg='" + msg + '\'' +
                '}';
    }

    WstbException(String s){
        msg = s;
    }

}
