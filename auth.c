#include "auth.h"
#include "sockp.h"

#define INSERT_INTO_AUTH_PROCEDURE(sb, auth_stage)  \
    do {                \
        if (!(sb)->auth_procedure)  \
        (sb)->auth_procedure = auth_stage;  \
        if (sb->auth_procedure_tail)    \
        (sb)->auth_procedure_tail->next = auth_stage;   \
        (sb)->auth_procedure_tail = auth_stage; \
    } while (0);


int check_if_ignore_auth_procedure(int fd, const char __user *buf, size_t len, char io_type)
{
    struct socket_bucket *sb;
    struct socket *sock;
    struct sockaddr servaddr;

    if (!is_sock_fd(fd))
        return 0;

    sock = getsock(fd);
    if (!sock 
            || !IS_TCP_SOCK(sock) 
            || !IS_CLIENT_SOCK(sock))
        return 0;

    if (!getsockservaddr(sock, &servaddr))
        return 0;
    
    if (!IS_IPV4_SA(&servaddr))
        return 0;


    if (!(sb = get_auth_sb(servaddr)))
        return 0;

    if (sb->auth_status == AUTH_PROCESSING) {
        if (!sb->auth_stage) {
            struct auth_stage *cfg_auth_procedure = cfg_conn_get_auth_procedure(servaddr);
            if (!cfg_auth_procedure) {
                sb->auth_status = AUTH_FAIL;
                return 0;
            }

            sb->auth_stage = cfg_auth_procedure;
        }

        while (sb->auth_stage->type == 'i') { //strip the POLLIN
            struct auth_stage *auth_stage;
            auth_stage = lkmalloc(sizeof(*auth_stage));
            if (!auth_stage) {
                printk(KERN_ERR "No more memory!");
                sb->auth_status = AUTH_FAIL;
                return 0;
            }
            auth_stage->type = 'i';
            INSERT_INTO_AUTH_PROCEDURE(sb, auth_stage);
            sb->auth_stage = sb->auth_stage->next;
        }

        if (!sb->auth_stage || sb->auth_stage->type != io_type) {
            printk(KERN_ERR "Auth procedure is not correct!");
            sb->auth_status = AUTH_FAIL;
            return 0;
        }

        if (io_type == 'r') { //read
            unsigned int count;
            count = orig_sys_read(fd, buf, len); 
            if (count) {
                struct auth_stage *auth_stage;
                auth_stage = lkmalloc(sizeof(*auth_stage));
                if (!auth_stage) {
                    printk(KERN_ERR "Mo more memory!");
                    sb->auth_status = AUTH_FAIL;
                    return 0;
                }
                auth_stage->type = 'r';
                auth_stage->data.data = lkmalloc(count);
                if (!auth_stage->data.data) {
                    printk(KERN_ERR "No more memory!");
                    sb->auth_status = AUTH_FAIL;
                    lkmfree(auth_stage);
                    return 0;
                }
                if (copy_from_user(auth_stage->data.data, buf, count) 
                        || memcmp(auth_stage->data.data, sb->auth_stage->data.data, sb->auth_stage->data.len)) {
                    printk(KERN_ERR "Copy mem error or auth procedure const data is not correct!");
                    sb->auth_status = AUTH_FAIL;
                    lkmfree(auth_stage->data.data);
                    lkmfree(auth_stage);
                    return 0;
                }

                auth_stage->data.len = count;
                
                INSERT_INTO_AUTH_PROCEDURE(sb, auth_stage);

                return count;
            }            
        } else { //'w'
            struct auth_stage *auth_stage;
            auth_stage = lkmalloc(sizeof(*auth_stage));
            if (!auth_stage) {
                printk(KERN_ERR "No more memory!");
                sb->auth_status = AUTH_FAIL;
                return 0;
            }
            
            auth_stage->type = 'w';            
            auth_stage->data.data = lkmalloc(len);
            if (!auth_stage->data.data) {
                printk(KERN_ERR "No more memory!");
                sb->auth_status = AUTH_FAIL;
                lkmfree(auth_stage);
                return 0;
            }
            if (!copy_from_user(auth_stage->data.data, buf, len)) {
                auth_stage->data.len = len; 
                INSERT_INTO_AUTH_PROCEDURE(sb, auth_stage);
            } else {
                sb->auth_status = AUTH_FAIL;
                lkmfree(auth_stage->data.data);
                lkmfree(auth_stage);
            }

            return 0;
        }

        if (!sb->auth_stage->next)  //last procedure step.
            sb->auth_status = AUTH_SUCCESS;

        sb->auth_stage = sb->auth_stage->next;

        if (sb->auth_generation != cfg->auth_generation) {
            sb->auth_status = AUTH_FAIL;
            return 0;
        }

    } else if (sb->auth_status == AUTH_SUCCESS) {

    }

    return 0;
}
