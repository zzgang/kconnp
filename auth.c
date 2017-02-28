#include "auth.h"
#include "sockp.h"
#include "cfg.h"
#include "sys_call.h"

#define INSERT_INTO_AUTH_PROCEDURE(sb, auth_stage)  \
    do {                \
        if (!(sb)->auth_procedure_head)  \
        (sb)->auth_procedure_head = auth_stage;  \
        if ((sb)->auth_procedure_tail)    \
        (sb)->auth_procedure_tail->next = auth_stage;   \
        (sb)->auth_procedure_tail = auth_stage; \
    } while (0);

int check_if_ignore_auth_procedure(int fd, const char __user *buf, size_t len, 
        char io_type)
{
    struct socket_bucket *sb;
    struct socket *sock;
    struct sockaddr servaddr;
    int ret = 0;

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

    if (!(sb = get_auth_sb(sock->sk)))
        return 0;


    if (sb->auth_procedure_status == AUTH_FAIL) 
        return 0;

    if (sb->auth_procedure_head && !sb->auth_procedure_stage) 
        return 0;

    if (sb->cfg_generation != cfg->auth_generation) {
        sb->auth_procedure_status = AUTH_FAIL;
        return 0;
    }

    if (io_type == 'i') {
        if (sb->auth_procedure_status == AUTH_SUCCESS)
            return POLLIN;
        else 
            return 0;
    }
    
    //printk(KERN_ERR "debug io_type entry: %d", io_type);

    if (sb->auth_procedure_status == AUTH_PROCESSING) {
        struct conn_node_t *conn_node = cfg_conn_get_node(&servaddr);
        if (!conn_node) 
            return 0;
        if (!sb->auth_procedure_stage) {
            struct auth_stage *cfg_auth_procedure = NULL;
            if (conn_node->auth_node)
                cfg_auth_procedure = conn_node->auth_node->data;

            if (!cfg_auth_procedure) {
                sb->auth_procedure_status = AUTH_FAIL;
                return 0;
            }

            sb->auth_procedure_stage = cfg_auth_procedure;
        }

        if (!sb->auth_procedure_stage || sb->auth_procedure_stage->type != io_type) {
            printk(KERN_ERR "debug sb-type: %d, io_type: %d", sb->auth_procedure_stage->type, io_type);
            printk(KERN_ERR "Auth procedure (service: %s) is not corresponding!", conn_node->conn_sn.data);
            sb->auth_procedure_status = AUTH_FAIL;
            return 0;
        }

        if (io_type == 'r') { //read
            unsigned int count;
            count = orig_sys_read(fd, buf, len); 
            if (count) {
                struct auth_stage *auth_stage;
                auth_stage = lkmalloc(sizeof(*auth_stage));
                if (!auth_stage) {
                    printk(KERN_ERR "No more memory!");
                    sb->auth_procedure_status = AUTH_FAIL;
                    return 0;
                }
                auth_stage->type = 'r';
                auth_stage->info.data = lkmalloc(count);
                if (!auth_stage->info.data) {
                    printk(KERN_ERR "No more memory!");
                    sb->auth_procedure_status = AUTH_FAIL;
                    lkmfree(auth_stage);
                    return 0;
                }
                if (copy_from_user(auth_stage->info.data, buf, count) 
                        || (sb->auth_procedure_stage->info.len 
                            && memcmp(auth_stage->info.data, sb->auth_procedure_stage->info.data, sb->auth_procedure_stage->info.len))) {
                    printk(KERN_ERR "Copy mem error or auth procedure const data is not correct! count: %d, len: %d", count, sb->auth_procedure_stage->info.len);
                    sb->auth_procedure_status = AUTH_FAIL;
                    lkmfree(auth_stage->info.data);
                    lkmfree(auth_stage);
                    return 0;
                } /*else 
                    printk(KERN_ERR "Corresponding\n");*/

                auth_stage->info.len = count;
                
                INSERT_INTO_AUTH_PROCEDURE(sb, auth_stage);

                ret = count;
                goto out_auth_processing;
            }            
        } else { //'w'
            struct auth_stage *auth_stage;
            auth_stage = lkmalloc(sizeof(*auth_stage));
            if (!auth_stage) {
                printk(KERN_ERR "No more memory!");
                sb->auth_procedure_status = AUTH_FAIL;
                return 0;
            }
            
            auth_stage->type = 'w';            
            auth_stage->info.data = lkmalloc(len);
            if (!auth_stage->info.data) {
                printk(KERN_ERR "No more memory!");
                sb->auth_procedure_status = AUTH_FAIL;
                lkmfree(auth_stage);
                return 0;
            }
            if (!copy_from_user(auth_stage->info.data, buf, len)) {
                auth_stage->info.len = len; 
                INSERT_INTO_AUTH_PROCEDURE(sb, auth_stage);
                ret = 0;
                goto out_auth_processing;
            } else {
                sb->auth_procedure_status = AUTH_FAIL;
                lkmfree(auth_stage->info.data);
                lkmfree(auth_stage);
                return 0;
            }
        }

out_auth_processing:

        if (!sb->auth_procedure_stage->next)   //last procedure step.
            sb->auth_procedure_status = AUTH_SUCCESS;
        
        sb->auth_procedure_stage = sb->auth_procedure_stage->next;

        return ret;

    } else if (sb->auth_procedure_status == AUTH_SUCCESS) {
        if (!sb->auth_procedure_head) {
            printk(KERN_ERR "Auth procedure is not exists!");
            return 0;
        }

        if (!sb->auth_procedure_stage) {
            printk(KERN_ERR "Auth procedure head is not set!");
            return 0;
        }

        if (sb->auth_procedure_stage->type != io_type) {
            printk(KERN_ERR "Auth procedure is not corresponding!");
            return 0;
        }

        if (io_type == 'r') {
            if (!sb->auth_procedure_stage->info.len) {
                printk(KERN_ERR "Auth procedure data for reading is empty!");
                return 0;
            }
            
            //printk(KERN_ERR "user len: %d, info_len: %d\n", len, sb->auth_procedure_stage->info.len);
            if (copy_to_user((void *)buf, sb->auth_procedure_stage->info.data, sb->auth_procedure_stage->info.len)) {
                printk(KERN_ERR "Auth procedure copy data error!");
                return 0;
            }

            ret = sb->auth_procedure_stage->info.len;
            goto out_auth_success;
        } else {//'w'
            /*
            kconnp_str_t str;
            str.data = lkmalloc(len);
            if (!str.data) {
                printk(KERN_ERR "No more memory!");
                return 0;
            } 

            if (copy_from_user(str.data, buf, len)) {
                printk(KERN_ERR "Auth procedure copy data error!");
                lkmfree(str.data);
                return 0;
            }

            if (len != sb->auth_procedure_stage->info.len 
                    || memcmp(str.data, sb->auth_procedure_stage->info.data, len)) {
                int i = 0;
                printk(KERN_INFO "Auth procedure data for writing is not corresponding! len: %d, info-len: %d", len, sb->auth_procedure_stage->info.len);
                while (i < len) {
                    printk(KERN_ERR "str-data: %d\n", str.data[i]);
                    printk(KERN_ERR "auth_procedure_stage-data: %d\n", sb->auth_procedure_stage->info.data[i]);
                    if (str.data[i] != sb->auth_procedure_stage->info.data[i]) {
                        printk(KERN_ERR "writing data is not coresponding!i:%d", i);
                    }
                    i++;
                }
            }

            lkmfree(str.data);
            */
            ret = len;
            goto out_auth_success;
        }

out_auth_success:
        sb->auth_procedure_stage = sb->auth_procedure_stage->next;
        return ret;
    }

    return 0;
}
