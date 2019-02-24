package com.yunjingit.common;


import com.sun.jna.Pointer;


public class WstbContext {

    public int getDevice_type() {
        return device_type;
    }

    public void setDevice_type(int device_type) {
        this.device_type = device_type;
    }

    int device_type;

    byte[] api_version= new byte[33];

    public int getDevice_count() {
        return device_count;
    }

    public void setDevice_count(int device_count) {
        this.device_count = device_count;
    }

    int device_count;

    boolean protect_key;

    public DeviceContext[] getDevice_list() {
        return device_list;
    }

    public void setDevice_list(DeviceContext[] device_list) {
        this.device_list = device_list;
    }

    DeviceContext[] device_list= new DeviceContext[8];

    public boolean setDeviceContext(int index, Pointer hdevice, Pointer hpipe, Pointer hauthkey){
        if(device_list[index] != null){
            System.out.println("device  [" + index + "] is already open!");
            return false;
        }
        DeviceContext deviceContext = new DeviceContext();
        deviceContext.setH_device(hdevice);
        deviceContext.setH_auth(hauthkey);
        if(deviceContext.setHpipe(0,hpipe)){
            device_list[index] = deviceContext;
            System.out.printf("device[%d] successfully OPENED! \n", index);
        }else {
            return false;
        }

        return true;
    }

    public boolean logout(int index){
        DeviceContext dev = device_list[index];
        if(dev == null){
            System.out.println("device [" + index + "] is not open!");
            return true;
        }
        if(dev.destroyKeys()){
            Pointer hpipe = dev.getOpenedPipe();
            if(dev.h_auth_key!=null){
               int ret = WstbApi.INSTANCE.SM_CloseTokKeyHdl(hpipe,dev.h_auth_key);
               if(ret != WstbApi.SM_ERR_FREE){
                   System.out.printf("SM_CloseTokKeyHdl error %d \n", ret);
                   return false;
               }else{
                   System.out.printf("SM_CloseTokKeyHdl success! \n");
               }
            }
            int res = WstbApi.INSTANCE.SM_Logout(hpipe);
            if(res != WstbApi.SM_ERR_FREE){
                System.out.printf("SM_Logout  failed  %d \n",  res);
                return false;
            }

            res = WstbApi.INSTANCE.SM_CloseAllSecPipe(dev.h_device);
            if(res != WstbApi.SM_ERR_FREE){
                System.out.printf("SM_CloseAllSecPipe  failed  %d \n",  res);
                return false;
            }

            res = WstbApi.INSTANCE.SM_CloseDevice(dev.h_device);
            System.out.println("SM_CloseDevice result " + res);
            return true;
        }
        return false;
    }

    public Pointer getDevicePipe(int index) {
        DeviceContext dev = device_list[index];
        if(dev == null){
            System.out.println("device  [" + index + "] is not open!");
            return null;
        }

        return dev.getOpenedPipe();
    }

    public Pointer getDeviceAuthKey(int index) {
        DeviceContext dev = device_list[index];
        if(dev == null){
            System.out.println("device  [" + index + "] is not open!");
            return null;
        }

        return dev.getH_auth();
    }
}

class DeviceContext{
    static final int MAX_MECHANISM_LEN =  32;
    static final int MAX_PIPE_LEN    =    32;
    static final int MAX_CODE_LEN    =    64;

    int index;
    int check_result;
    int[] codes=new int[MAX_CODE_LEN];
    int codes_len;
    int logged_in;
    WstbApi.SM_MECHANISM_INFO[] mechanism_list = new WstbApi.SM_MECHANISM_INFO[MAX_MECHANISM_LEN];
    int mechanisms_len;
    WstbApi.SM_DEVICE_INFO device_info ;

    public Pointer getH_device() {
        return h_device;
    }

    public void setH_device(Pointer h_device) {
        this.h_device = h_device;
    }

    Pointer h_device;

    Pointer h_auth_key;
    public Pointer getH_auth() {
        return h_auth_key;
    }

    public void setH_auth(Pointer h_device) {
        this.h_auth_key = h_device;
    }

    Pointer[] h_pipes= new Pointer[MAX_PIPE_LEN];
    Pointer[] h_keys= new Pointer[MAX_PIPE_LEN];
    int pipes_len=0;

    public boolean setHpipe(int pipeIndex, Pointer p){
        if(h_pipes[pipeIndex]!=null){
            return false;
        }

        h_pipes[pipeIndex] = p;
        pipes_len ++;
        return true;
    }

    public boolean destroyKeys(){
        boolean result = true;
        for(int i=0; i<MAX_PIPE_LEN;i++){
            Pointer hpipe = h_pipes[i];
            Pointer hkey = h_keys[i];
            if((hpipe!=null) && (hkey!=null)){
                int ret = WstbApi.INSTANCE.SM_DestroyKey(hpipe,hkey);
                if(ret == WstbApi.SM_ERR_FREE){
                    h_keys[i] = null;
                }else{
                    System.out.printf(" SM_DestroyKey %d  error %d \n" , i, ret);
                    result = false;
                }
            }
        }
        return result;
    }




    public Pointer getOpenedPipe(){
        Pointer p = null;
        for(int i=0;i<pipes_len;i++){
            p = h_pipes[i];
            if(p!=null){
                return p;
            }
        }
        return null;
    }

}