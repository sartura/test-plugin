#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>

#include <sysrepo.h>
#include <sysrepo/plugins.h>
#include <sysrepo/values.h>

#include "common.h"

const char *yang_model = "test-plugin";

typedef struct ctx_s {
    const char *yang_model;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub;
} ctx_t;

static int rpc_cb(__attribute__((unused)) const char *xpath,
                  const sr_val_t *input,
                  __attribute__((unused)) const size_t input_cnt,
                  sr_val_t **output,
                  size_t *output_cnt,
                  __attribute__((unused)) void *private_ctx)
{
    int rc = SR_ERR_OK;
    FILE *f = NULL;
    char buf[100] = {0};
    char *response = NULL;
    char *temp = NULL;
    unsigned int size = 1;
    unsigned int strlength;

    CHECK_NULL_MSG(input, &rc, error, "input is empty");

    f = popen(input[0].data.string_val, "r");
    CHECK_NULL(f, &rc, error, "failed to run command: \"%s\"", input[0].data.string_val);

    while (fgets(buf, sizeof(buf), f) != NULL) {
        strlength = strlen(buf);
        temp = realloc(response, size + strlength);
        CHECK_NULL(temp, &rc, error, "failed realloc for command: \"%s\"", input[0].data.string_val);
        response = temp;
        strcpy(response + size - 1, buf);
        size += strlength;
    }

    rc = sr_new_values(1, output);
    CHECK_RET(rc, error, "failed sr_new_values %s", sr_strerror(rc));
    *output_cnt = 1;
    sr_val_set_xpath(*output, "/test-plugin:call/response");
    sr_val_set_str_data(*output, SR_STRING_T, response);

error:
    if (f) {
        pclose(f);
    }
    if (response) {
        free(response);
    }
    return rc;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    int rc = SR_ERR_OK;

    /* INF("sr_plugin_init_cb for sysrepo-plugin-dt-network"); */

    ctx_t *ctx = calloc(1, sizeof(*ctx));
    ctx->sub = NULL;
    ctx->sess = session;
    ctx->yang_model = yang_model;
    *private_ctx = ctx;

    /* subscribe for handling RPC */
    rc = sr_rpc_subscribe(session, "/test-plugin:call", rpc_cb, (void *) session, SR_SUBSCR_DEFAULT, &ctx->sub);
    CHECK_RET(rc, error, "failed sr_rpc_subscribe: %s", sr_strerror(rc));

    INF_MSG("Plugin initialized successfully");

    return SR_ERR_OK;

error:
    ERR("Plugin initialization failed: %s", sr_strerror(rc));
    if (NULL != ctx->sub) {
        sr_unsubscribe(ctx->sess, ctx->sub);
        ctx->sub = NULL;
    }

    return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");
    if (!private_ctx)
        return;

    ctx_t *ctx = private_ctx;
    if (NULL == ctx) {
        return;
    }
    if (NULL != ctx->sub) {
        sr_unsubscribe(session, ctx->sub);
    }
    free(ctx);

    DBG_MSG("Plugin cleaned-up successfully");
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum)
{
    INF_MSG("Sigint called, exiting...");
    exit_application = 1;
}

int main()
{
    INF_MSG("Plugin application mode initialized");
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    void *private_ctx = NULL;
    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    rc = sr_connect(yang_model, SR_CONN_DEFAULT, &connection);
    CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

    /* start session */
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

    rc = sr_plugin_init_cb(session, &private_ctx);
    CHECK_RET(rc, cleanup, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1); /* or do some more useful work... */
    }

cleanup:
    sr_plugin_cleanup_cb(session, private_ctx);
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
}
#endif
