#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/data.h"
#include "../include/device.h"
#include "../include/context.h"
#include "../include/crypto.h"
#include "../include/pipe.h"


static CryptoContext g_crypto_context;
static int init_statistics();
static int check_device_index(int index);
static int check_pipe_index(int device_index, int pipe_index);


void ctx_print_context(char *buf, int buf_len, bool verbose) {
    int delta = 0;
    char *cursor = buf;

    assert(buf_len >= 1024 * 32);

    delta = print_statistics(&g_crypto_context, cursor);
    cursor += delta;

    if (verbose) {
        int i;
        for (i = 0; i < g_crypto_context.device_count; i++) {
            DeviceContext *device_context = &(g_crypto_context.device_list[i]);
            if (NULL != device_context->h_device) {
                delta = print_device_context(device_context, cursor);
                cursor += delta;
            }
        }
    }
}

int ctx_open_device(int index) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    device_context->index = index;
    int error_code = dev_init_device(device_context);

    return error_code;
}

int ctx_close_device(int index) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }
    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    return dev_close_device(device_context);
}

int ctx_close_all_devices() {
    int i;
    for (i = 0; i < g_crypto_context.device_count; i++) {
        int error_code = ctx_close_device(i);
        if (error_code != YERR_SUCCESS) return error_code;
    }

    return YERR_SUCCESS;
}

int ctx_get_device_status(int index, DeviceStatus *device_status) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }

    memset(device_status, 0, sizeof(DeviceStatus));
    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    device_status->index = index;
    device_status->logged_in = device_context->logged_in;
    device_status->opened = NULL != device_context->h_device;
    device_status->check_result = device_context->check_result;

    return dev_pipes_count(device_context, &(device_status->max_pipes_count), &(device_status->free_pipes_count));
}

DeviceStatuses ctx_get_device_statuses() {
    DeviceStatuses device_statuses;
    memset(&device_statuses, 0, sizeof(device_statuses));

    int i;
    for (i = 0; i < g_crypto_context.device_count; i++) {
        ctx_get_device_status(i, &device_statuses.device_status_list[i]);
    }
    device_statuses.count = g_crypto_context.device_count;

    return device_statuses;
}

int ctx_device_count() {
    return g_crypto_context.device_count;
}

int ctx_check_device(int index) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    return dev_check_device(device_context);
}

int init() {
    int error_code = YERR_SUCCESS;
    error_code = crypto_init_context();
    if (error_code != YERR_SUCCESS) return error_code;

    error_code = init_statistics();
    if (error_code != YERR_SUCCESS) return error_code;

    return error_code;
}

int ctx_open_pipe(int index) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }

    int max_pipes_count = 0;
    int free_pipes_count = 0;
    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    int error_code = dev_pipes_count(device_context, &max_pipes_count, &free_pipes_count);
    if (error_code != YERR_SUCCESS) return error_code;

    error_code = pp_open_pipe(device_context, free_pipes_count);
    return error_code;
}

int ctx_close_pipe(int index) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    return pp_close_all_pipe(device_context);
}

int ctx_close_all_pipe(int index) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    return pp_close_all_pipe(device_context);
}

int ctx_login(int index, const char *pin_code) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    return pp_login(device_context, pin_code);
}

int ctx_logout(int index) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }

    DeviceContext *device_context = &(g_crypto_context.device_list[index]);
    return pp_logout(device_context);
}

int ctx_digest(int device_index, int pipe_index, const char *data, int data_len, char *out, int out_len) {
    int error_code = YERR_SUCCESS;

    error_code = check_pipe_index(device_index, pipe_index);
    if (error_code != YERR_SUCCESS) return error_code;

    DeviceContext *device_context = &(g_crypto_context.device_list[device_index]);
    pipe_index = abs(pipe_index);
    pipe_index %= device_context->pipes_len;

    SM_PIPE_HANDLE h_pipe = device_context->h_pipes[pipe_index];
    return crypto_digest(h_pipe, data, data_len, out, out_len);
}

static int init_statistics() {
    int error_code = YERR_SUCCESS;
    CryptoContext *crypto_context = &(g_crypto_context);

    int device_count = 0;
    error_code = SM_GetDeviceNum((PSM_UINT)&device_count);
    if (error_code != YERR_SUCCESS) return error_code;

    int device_type = 0;
    const char *api_version = SM_GetAPIVersion();

    error_code = SM_GetDeviceType((PSM_UINT)&device_type);
    if (error_code != YERR_SUCCESS) return error_code;

    strncpy(crypto_context->api_version, api_version,
            sizeof(crypto_context->api_version));
    crypto_context->device_type = device_type;
    crypto_context->device_count = device_count;

    return error_code;
}

static int check_device_index(int index) {
    if (index < 0 || index >= g_crypto_context.device_count) {
        return INDEX_OUTOF_BOUND;
    }
    return YERR_SUCCESS;
}

static int check_pipe_index(int device_index, int pipe_index) {
    int error_code = YERR_SUCCESS;

    error_code = check_device_index(device_index);
    if (error_code != YERR_SUCCESS) return error_code;

    DeviceContext *device_context = &(g_crypto_context.device_list[device_index]);
    if (NULL == device_context->h_device) {
        return DEVICE_NOT_OPENED;
    }
    if (device_context->pipes_len <= 0) {
        return PIPE_NOT_OPENED;
    }
    if (!device_context->logged_in) {
        return NEED_LOGIN;
    }

    return error_code;
}
