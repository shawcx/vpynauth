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


// OpenVPN exits when open fails without calling close, so release what was set up

static int open_failed(Handle *handle) {
    Py_XDECREF(handle->verify);
    Py_XDECREF(handle->module);
    free(handle);
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT
int openvpn_plugin_open_v3(const int structver, struct openvpn_plugin_args_open_in const *args, struct openvpn_plugin_args_open_return *ret) {
    if (OPENVPN_PLUGINv3_STRUCTVER != structver) {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

// callback hooks

    ovpn_log  = args->callbacks->plugin_log;

// allocate the handle

    Handle *handle = (Handle *)calloc(1, sizeof(Handle));
    if (NULL == handle) {
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Out of memory");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

// get the directory for the script and the import name

    const char *base_dir = args->argv[1];
    if (NULL == base_dir) {
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Usage: plugin %s <script_dir> [module]", args->argv[0]);
        return open_failed(handle);
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
        return open_failed(handle);
    }

// the handle is deliberately never closed: python outlives the plugin across SIGHUP
// reloads (see openvpn_plugin_close_v1), so libpython must stay mapped

    if (NULL == dlopen(info.dli_fname, RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD)) {
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Could not reload %s: %s", info.dli_fname, dlerror());
        return open_failed(handle);
    }

// only the first open initializes python; a reload reuses the running interpreter

    if(!Py_IsInitialized()) {
        Py_InitializeEx(0);
    }

// inject the script directory in the python path, once across reloads

    PyObject *sys_path = PySys_GetObject("path");
    if (NULL == sys_path) {
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Missing sys.path");
        return open_failed(handle);
    }

    PyObject *py_base_dir = PyUnicode_DecodeFSDefault(base_dir);
    int present = (NULL == py_base_dir) ? -1 : PySequence_Contains(sys_path, py_base_dir);
    if (present < 0 || (0 == present && 0 != PyList_Append(sys_path, py_base_dir))) {
        PyErr_Print();
        Py_XDECREF(py_base_dir);
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Could not add to sys.path: %s", base_dir);
        return open_failed(handle);
    }
    Py_DECREF(py_base_dir);

// import the script

    PyObject *py_script = PyUnicode_DecodeFSDefault(script);
    if (NULL == py_script) {
        PyErr_Print();
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Could not decode: %s", script);
        return open_failed(handle);
    }

    handle->module = PyImport_Import(py_script);
    Py_DECREF(py_script);

    if (NULL == handle->module) {
        PyErr_Print();
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Could not import: %s %s", base_dir, script);
        return open_failed(handle);
    }

    PyObject *Verify = PyObject_GetAttrString(handle->module, "Verify");
    if (NULL == Verify) {
        PyErr_Print();
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Missing 'Verify' class: %s %s", base_dir, script);
        return open_failed(handle);
    }

    handle->verify = PyObject_CallObject(Verify, NULL);
    Py_DECREF(Verify);

    if (NULL == handle->verify) {
        PyErr_Print();
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Could not instantiate 'Verify' class: %s %s", base_dir, script);
        return open_failed(handle);
    }

    ret->handle = handle;
    ret->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT
int openvpn_plugin_func_v1(openvpn_plugin_handle_t _handle, const int type, const char *argv[], const char *envp[]) {
    Handle *handle = (Handle *)_handle;

// only handle auth_user_pass

    if (type != OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) {
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Unsupported plugin call: %d", type);
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
            ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: Could not convert environment");
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    }

    PyObject *retval = PyObject_CallMethod(handle->verify, "auth", "(O)", vars);

    Py_DECREF(vars);

    if (NULL == retval) {
        PyErr_Print();
        ovpn_log(PLOG_ERR, PLUGIN_NAME, "ERROR: auth() call failed");
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
    if (NULL == handle) {
        return;
    }

// OpenVPN closes and reopens plugins on SIGHUP. Python is left running because C
// extensions (e.g. _hashlib) crash when imported again after Py_FinalizeEx. Instead the
// script is dropped from sys.modules, so the next open imports a fresh copy of it.

    PyObject *name = PyModule_GetNameObject(handle->module);
    if (NULL == name || 0 != PyDict_DelItem(PyImport_GetModuleDict(), name)) {
        PyErr_Clear();
    }
    Py_XDECREF(name);

    Py_XDECREF(handle->verify);
    Py_XDECREF(handle->module);

    free(handle);
}
