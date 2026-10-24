// for dladdr and RTLD_NOLOAD
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <Python.h>

#include <openvpn/openvpn-plugin.h>

#define PLUGIN_NAME "vpynauth"

static plugin_log_t ovpn_log  = NULL;

typedef struct {
    PyObject *module;
    PyObject *verify;
} Handle;


OPENVPN_EXPORT
int openvpn_plugin_open_v3(const int structver, struct openvpn_plugin_args_open_in const *args, struct openvpn_plugin_args_open_return *ret) {
    if (OPENVPN_PLUGINv3_STRUCTVER != structver) {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

// callback hooks

    ovpn_log  = args->callbacks->plugin_log;

// allocate the handle

    Handle *handle = (Handle *)malloc(sizeof(Handle));

    ret->handle = handle;
    ret->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

// get the directory for the script and the import name

    const char *base_dir = args->argv[1];
    if (NULL == base_dir) {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    const char *script = args->argv[2];
    if (NULL == script) {
        script = "vpynauth";
    }

// initialize python

    //PyImport_AppendInittab("vpynauth", &PyInit_vpynauth);

// promote the already loaded libpython to RTLD_GLOBAL so that python C extensions
// can resolve its symbols; dladdr finds the exact file this plugin was linked against

    Dl_info info;
    if (0 == dladdr((void *)&Py_IsInitialized, &info) || NULL == info.dli_fname) {
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Could not locate libpython");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    if (NULL == dlopen(info.dli_fname, RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD)) {
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Could not reload %s: %s", info.dli_fname, dlerror());
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    if(!Py_IsInitialized()) {
        Py_InitializeEx(0);
    }

// inject the script directory in the python path

    PyObject *sys_path = PySys_GetObject("path");
    if (NULL == sys_path) {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    PyObject *py_base_dir = PyUnicode_DecodeFSDefault(base_dir);
    PyList_Append(sys_path, py_base_dir);
    Py_DECREF(py_base_dir);

// import the script

    PyObject *py_script = PyUnicode_DecodeFSDefault(script);
    if (NULL == py_script) {
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Could not decode: %s", script);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    handle->module = PyImport_Import(py_script);
    Py_DECREF(py_script);

    if (NULL == handle->module) {
        PyErr_Print();
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Could not import: %s %s", base_dir, script);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    PyObject *Verify = PyObject_GetAttrString(handle->module, "Verify");
    if (NULL == Verify) {
        PyErr_Print();
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Missing 'Verify' class: %s %s", base_dir, script);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    handle->verify = PyObject_CallObject(Verify, NULL);

    if (NULL == handle->verify) {
        PyErr_Print();
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Coudl not instantiate 'Verify' class: %s %s", base_dir, script);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT
int openvpn_plugin_func_v1(openvpn_plugin_handle_t _handle, const int type, const char *argv[], const char *envp[]) {
    Handle *handle = (Handle *)_handle;

// only handle auth_user_pass

    if (type != OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) {
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "Unsupported plugin call: %d\n", type);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

// convert envp to a dict; bytes that aren't valid UTF-8 (e.g. in a password)
// become surrogate escapes instead of failing the decode

    PyObject *vars = PyDict_New();
    if (NULL == vars) {
        PyErr_Print();
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    for (int idx = 0; envp[idx]; ++idx) {
        const char *eq = strchr(envp[idx], '=');
        if (NULL == eq) {
            continue;
        }

        PyObject *key = PyUnicode_DecodeUTF8(envp[idx], eq - envp[idx], "surrogateescape");
        PyObject *val = PyUnicode_DecodeUTF8(eq + 1, strlen(eq + 1), "surrogateescape");

        int err = (NULL == key || NULL == val) ? -1 : PyDict_SetItem(vars, key, val);

        Py_XDECREF(key);
        Py_XDECREF(val);

        if (err < 0) {
            PyErr_Print();
            Py_DECREF(vars);
            ovpn_log(PLOG_ERR, PLUGIN_NAME, "Could not convert environment");
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    }

    PyObject *method = PyUnicode_FromString("auth");

    PyObject *retval = PyObject_CallMethodObjArgs(handle->verify, method, vars, NULL);

    Py_DECREF(vars);
    Py_DECREF(method);

    if (NULL == retval) {
        PyErr_Print();
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "Authentication error failed\n");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

// only an exact int 0 or True accepts; False (which == 0), None, other values
// and overflowing ints all reject

    int accept = (Py_True == retval) || (PyLong_CheckExact(retval) && 0 == PyLong_AsLong(retval));

    if (PyErr_Occurred()) {
        PyErr_Print();
    }

    Py_DECREF(retval);

    return accept ? OPENVPN_PLUGIN_FUNC_SUCCESS : OPENVPN_PLUGIN_FUNC_ERROR;
}


OPENVPN_EXPORT
void openvpn_plugin_close_v1(openvpn_plugin_handle_t _handle) {
    Handle *handle = (Handle *)_handle;

    Py_DECREF(handle->verify);
    Py_DECREF(handle->module);

    if(Py_IsInitialized()) {
        Py_FinalizeEx();
    }

    struct Handle *context = (struct Handle *)handle;
    if (NULL != context) {
        free(context);
        context = NULL;
    }
}
