#ifndef DATA_H
#define DATA_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DEVICE_STATUS_NUMBER   8


typedef struct {
    int index;
    bool opened;
    int check_result;
    int logged_in;
    int max_pipes_count;
    int free_pipes_count;
} DeviceStatus;

typedef struct {
    int count;
    DeviceStatus device_status_list[MAX_DEVICE_STATUS_NUMBER];
} DeviceStatuses;


#ifdef __cplusplus
}
#endif

#endif
