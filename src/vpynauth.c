#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#define _STR(x) #x
#define STR(x) _STR(x)

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

    dlopen("libpython" STR(PY_MAJOR_VERSION) "." STR(PY_MINOR_VERSION) ".so", RTLD_LAZY | RTLD_GLOBAL);

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
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Missing 'Verify' class: %s %s", base_dir, script);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    handle->verify = PyObject_CallObject(Verify, NULL);

    if (NULL == handle->verify) {
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

    PyObject *method = PyUnicode_FromString("auth");

    PyObject *vars = PyList_New(0);
    for (int idx = 0; envp[idx]; ++idx) {
        PyObject *var = PyUnicode_FromString(envp[idx]);
        PyList_Append(vars, var);
        Py_DECREF(var);
    }

    PyObject *retval = PyObject_CallMethodObjArgs(handle->verify, method, vars, NULL);

    Py_DECREF(vars);
    Py_DECREF(method);

    if (NULL == retval) {
        PyErr_Print();
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "Authentication error failed\n");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    long status = PyLong_AsLong(retval);

    Py_DECREF(retval);

    return status == 0 ? OPENVPN_PLUGIN_FUNC_SUCCESS : OPENVPN_PLUGIN_FUNC_ERROR;
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
