package com.yunjingit.common.Crypto;

public class TokenContext {

    public TokenContext(int deviceIndex, int pipeIndex) {
        this.deviceIndex = deviceIndex;
        this.pipeIndex = pipeIndex;
    }

    int deviceIndex;
    int pipeIndex;

    public void setDeviceIndex(int deviceIndex) {
        this.deviceIndex = deviceIndex;
    }

    public void setPipeIndex(int pipeIndex) {
        this.pipeIndex = pipeIndex;
    }

    public int getDeviceIndex() {
        return deviceIndex;
    }

    public int getPipeIndex() {
        return pipeIndex;
    }
}
