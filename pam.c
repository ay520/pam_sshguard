#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>   // 用于 mkdir 函数
#include <stdarg.h> // 为了使用 va_list
#include <time.h>  // 为了获取当前时间
#include <stdbool.h>
#include "config_parser.c"


#define MAX_READ_LINES 100000   // 读取的最大行数
#define MAX_LINE_LENGTH 256      // 每行读取的最大长度
#define MAX_PATH_LENGTH 512

#define CONFIG_FILE "/etc/pam_config.conf"

static char  IPWHITE_FILE[MAX_PATH_LENGTH] ="/etc/pam_allowed_ips.conf";
static char  WEAK_DIC_FILE[MAX_PATH_LENGTH] ="/etc/pam_weakpass_dic.conf";
static char  LOG_FILE[MAX_PATH_LENGTH] ="/var/log/pam_security.log"; // 自定义日志文件
static  int log_pass=0;//是否记录密码日志，1 开启
static  int exec_hook=0; //是否开启execve hook 注入， 1 开启

static char  PRELOAD_PATH[MAX_PATH_LENGTH] = "/lib64/security/libexecve_filter.so"; // pre_load so文件路径

static char *config_contents_ips[MAX_READ_LINES];
static int config_contents_ips_count=0;

static char *config_contents_dic[MAX_READ_LINES];
static int config_contents_dic_count=0;

static int module_initialized = 0;
static char global_password[100];
static int auth_type=0;


// 日志类型定义
#define LOG_INFO    6
#define LOG_WARNING 4
#define LOG_ERROR   3

static int load_config(const char *filename, char *config_contents[]);
static void pam_log(int log_level, const char *format, ...);
static int is_weak_password(const char *password, const char *username);
static int ip_in_range(const char *ip, const char *range);
static int check_ip(const char *ip);
static void pam_send_message(pam_handle_t *pamh, const char *msg);
static void free_config_contents(char *config_contents[], int count);


// 日志写入函数，支持日志级别和格式化字符串
static void pam_log(int log_level, const char *format, ...) {
    // 获取日志文件的目录路径
    char log_dir[256];
    strcpy(log_dir, LOG_FILE); // 复制日志文件路径
    char *last_slash = strrchr(log_dir, '/'); // 找到最后一个 '/' 位置

    if (last_slash) {
        *last_slash = '\0'; // 将最后一个 '/' 替换为 null 字符，以获取目录路径
        // 检查日志目录是否存在，不存在则创建
        if (access(log_dir, F_OK) == -1) { // 如果目录不存在
            mkdir(log_dir, 0644); // 创建目录，权限为 644 读写权限
        }
        *last_slash = '/'; // 恢复 '/' 字符
    }


    FILE *log_file = fopen(LOG_FILE, "a"); // 以追加模式打开日志文件
    if (log_file) {
        // 获取当前时间
        time_t now;
        time(&now);
        struct tm *tm_info = localtime(&now);
        
        // 格式化时间字符串
        char time_buf[20];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
        
        // 根据日志级别生成日志前缀
        const char *level_str;
        switch (log_level) {
            case LOG_INFO:    level_str = "INFO"; break;
            case LOG_WARNING: level_str = "WARNING"; break;
            case LOG_ERROR:   level_str = "ERROR"; break;
            default:          level_str = "UNKNOWN"; break;
        }

        // 写入日志时间、日志级别和信息到文件
        fprintf(log_file, "[%s] [%s]: ", time_buf, level_str);

        // 处理格式化的可变参数
        va_list args;
        va_start(args, format);
        vfprintf(log_file, format, args); // 使用 vfprintf 对格式化参数进行写入
        va_end(args);
        
        fprintf(log_file, "\n"); // 添加换行符
        fclose(log_file); // 关闭文件
    }
}




static int is_weak_password(const char *password,const char *username) {
    // 这里可以实现你的弱口令检测逻辑
    // 例如：简单的弱口令规则检测
    if (strlen(password) < 8) return 1; // 力度机制示例：长度小于 8 输即为弱口令
    if (strspn(password, "abcdefghijklmnopqrstuvwxyz") == strlen(password)) return 1; // 仅小写字母
    if (strspn(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == strlen(password)) return 1; // 仅大写字母
    if (strspn(password, "0123456789") == strlen(password)) return 1; // 仅数字
    if (strcmp(password,username)==0) return 1; //用户名密码相同
    

    // 可以添加更多规则，比如字典攻击、连续字符等

    for (int i = 0; i < config_contents_dic_count; i++) {
        if (strcmp(password,config_contents_dic[i])==0) {
            return 1; // 允许的 IP
        }
    }

    char username_with_weak_combination[100]={0};
    for( int i=0; i<config_contents_dic_count; i++){
         snprintf(username_with_weak_combination, sizeof(username_with_weak_combination), "%s@%s", username, config_contents_dic[i]); // username@weakpass
        if (strcmp(password, username_with_weak_combination) == 0) {
            return 1; // 认为是弱口令
        }

    }

    
    return 0; // 如果通过所有检查则认为是强口令
}


// 加载允许的IP地址，同时去重
static int load_config(const char *filename,char *config_contents[]) {
    int readline_count = 0;
    FILE *file = fopen(filename, "r");
    if (!file) {

        pam_log(LOG_WARNING,"PAM: Unable to open config file: %s", filename);
        return -1;
    }

    char line_buffer[MAX_LINE_LENGTH]; // 每行读取最大长度

    // 使用一个简单的哈希集合来存储已读取的行
    bool *seen = calloc(MAX_READ_LINES, sizeof(bool)); // 追踪已添加的行
    if (!seen) {
        pam_log(LOG_ERROR, "Memory allocation for seen array failed.");
        fclose(file);
        return -1; // 内存分配失败，返回错误
    }

    while (fgets(line_buffer, sizeof(line_buffer), file) && readline_count < MAX_READ_LINES) {
        line_buffer[strcspn(line_buffer, "\n")] = '\0'; // 去掉换行符

        // 检查当前行是否已存在，利用简单的哈希查找避免重复
        unsigned long hash = 0; // 计算简单的哈希值
        for (int i = 0; line_buffer[i] != '\0'; i++) {
            hash = (hash * 31) + line_buffer[i]; // 基于字符生成哈希值
        }
        int index = hash % MAX_READ_LINES; // 哈希值取模，每次都能生成 1～MAX_READ_LINES 之间的数，作为索引值

        // 如果没有看到这个索引的行，正常处理
        if (!seen[index]) {
            seen[index] = true; // 将此索引标记为已见

            config_contents[readline_count] = strdup(line_buffer); // 复制 IP 地址
            if (!config_contents[readline_count]) {
                pam_log(LOG_ERROR, "Memory allocation failed.");
                fclose(file);
                return -1; // 内存分配失败
            }
            readline_count++;
        }
    }
    fclose(file);
    free(seen);

    return readline_count;
}

static void free_config_contents(char *config_contents[], int count) {
    for (int i = 0; i < count; i++) {
        free(config_contents[i]); // 释放每个动态分配的字符串
    }
}


// 检查IP是否在范围内
static int ip_in_range(const char *ip, const char *range) {

    struct sockaddr_storage addr, net;
    //socklen_t addr_len, net_len;
    char *mask_str = strchr(range, '/'); // 查找分隔符

    // 如果存在子网掩码
    if (mask_str) {
        *mask_str = 0; // 将 '/' 替换为 null 字符，以便后续处理
        int mask = atoi(mask_str + 1); // 获取掩码的值
        int iptype=0;
        
        // 解析输入的 IP 地址
        if (inet_pton(AF_INET, ip, &((struct sockaddr_in *)&addr)->sin_addr) == 1) {
            //addr_len = sizeof(struct sockaddr_in);
            ((struct sockaddr_in *)&addr)->sin_family = AF_INET; // IPv4
            iptype=1;
        } else if (inet_pton(AF_INET6, ip, &((struct sockaddr_in6 *)&addr)->sin6_addr) == 1) {
            //addr_len = sizeof(struct sockaddr_in6);
            ((struct sockaddr_in6 *)&addr)->sin6_family = AF_INET6; // IPv6
            iptype=2;
        } else {
            return 0; // 无法解析 IP
        }

        // 解析范围IP
        if(iptype==1){
            if (inet_pton(AF_INET, range, &((struct sockaddr_in *)&net)->sin_addr) == 1) {
                //net_len = sizeof(struct sockaddr_in);
                ((struct sockaddr_in *)&net)->sin_family = AF_INET; // IPv4处理
                unsigned int ip_mask = htonl(~((1 << (32 - mask)) - 1)); // 计算网络掩码
                return (((struct sockaddr_in *)&addr)->sin_addr.s_addr & ip_mask) ==
                       (((struct sockaddr_in *)&net)->sin_addr.s_addr & ip_mask); //计算当前IP&掩码的与值 是否 与 ip range的掩码值相等

            }
            return 0;
        }
        
        if(iptype==2){
            if (inet_pton(AF_INET6, range, &((struct sockaddr_in6 *)&net)->sin6_addr) == 1) {
                //net_len = sizeof(struct sockaddr_in6);
                ((struct sockaddr_in6 *)&net)->sin6_family = AF_INET6; // IPv6处理
                unsigned char mask_bytes[16] = {0}; // 存储IPv6掩码字节数组
                int byte_mask = mask / 8; // 得到完整的字节数
                int bit_mask = mask % 8; // 得到剩余的位数

                // 用 0xFF 填充前面的字节
                memset(mask_bytes, 0xFF, byte_mask);
                if (bit_mask > 0) {
                    mask_bytes[byte_mask] = (unsigned char)(0xFF << (8 - bit_mask)); // 设置最后一个字节的有效位
                }
                // 比较掩码处理过后的地址
                return memcmp(&((struct sockaddr_in6 *)&addr)->sin6_addr, 
                            &((struct sockaddr_in6 *)&net)->sin6_addr, 
                            16) == 0;
            }
            return 0;
        }
    } else {
        // 如果没有子网掩码，直接比较 IP
        return strcmp(ip, range) == 0;
    }

    return 0;
}

// 检查给定 IP 是否在允许的范围内
static int check_ip(const char *ip) {

    for (int i = 0; i < config_contents_ips_count; i++) {
        if (ip_in_range(ip, config_contents_ips[i])) {
            return 1; // 允许的 IP
        }
    }

    return 0; // 不允许的 IP
}

// PAM 对话函数
static void pam_send_message(pam_handle_t *pamh, const char *msg) {
    struct pam_message message;
    const struct pam_message *messages[1];
    struct pam_response *responses = NULL;
    message.msg_style = PAM_ERROR_MSG;
    message.msg = msg;
    messages[0] = &message;
    struct pam_conv *conv;
    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS) {
        return;
    }
    int retval = conv->conv(1, messages, &responses, conv->appdata_ptr);
    if (retval == PAM_SUCCESS && responses) {
        free(responses[0].resp);
        free(responses);
    }
}

// 认证函数
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {

   
    const char *username;
    char *user_ip = NULL;
    const void *password; 
    int retval;
    auth_type=1;
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        return retval;
    }
    retval = pam_get_item(pamh, PAM_RHOST, (const void **)&user_ip);
    if (retval != PAM_SUCCESS) {
        return retval;
    }
    
    // retval = pam_get_authtok(pamh, PAM_AUTHTOK, (const char **)&password, NULL);
    // if (retval != PAM_SUCCESS) {
    //     return retval;
    // }

    retval = pam_get_item(pamh, PAM_AUTHTOK, &password);
    if (retval == PAM_SUCCESS && password != NULL) {

        strncpy(global_password,password,sizeof(global_password));
        return PAM_SUCCESS; 
    }

        
    return PAM_SUCCESS; 
    
}

// 账户管理函数
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {

   config_contents_ips_count=load_config(IPWHITE_FILE,config_contents_ips);
   config_contents_dic_count=load_config(WEAK_DIC_FILE,config_contents_dic);
    if (config_contents_ips_count < 1 || config_contents_dic_count < 1){
        pam_log(LOG_WARNING,"initialize error! can't load config file %s or %s,pls check them!",IPWHITE_FILE,WEAK_DIC_FILE); 
        return  PAM_SUCCESS;
    }else{

        module_initialized = 1;  
        pam_log(LOG_INFO, "PAM: config file %s: %d unique line loaded; config file %s:%d unique line loaded.", IPWHITE_FILE, config_contents_ips_count,WEAK_DIC_FILE,config_contents_dic_count);

    }
    const char *username;
    char *user_ip = NULL;
    int retval;
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        pam_log(LOG_WARNING, "PAM ACCOUNT: get account name error alert!");
        return retval;
    }
    retval = pam_get_item(pamh, PAM_RHOST, (const void **)&user_ip);
    if (retval != PAM_SUCCESS) {
        pam_log(LOG_WARNING, "PAM ACCOUNT: get user ip error alert!");
        return retval;
    }
    
    if (!check_ip(user_ip)) {
        char error_msg[1024] = {0};
        sprintf(error_msg,"Unauthorized IP address: [%s], Access denied.", user_ip);
        pam_send_message(pamh, error_msg);
        pam_log(LOG_INFO, "PAM ACCOUNT: Access denied for user: [%s] from unauthorized IP: [%s]", username, user_ip);
        return PAM_PERM_DENIED;
    }

    if(auth_type==0){//密钥登入
        pam_log(LOG_INFO, "PAM ACCOUNT: Authentication successful for user: [%s] with key from IP: [%s].", username, user_ip);
    }else{
         // 检查密码强度
         if (is_weak_password(global_password,username)) {
            pam_send_message(pamh, "Weak password detected, access denied. please change your password!");
            if(log_pass){
                pam_log(LOG_INFO, "PAM ACCOUNT: Weak password detected for user: [%s]  with password: [%s] from IP:[%s] and access denied!", username,global_password,user_ip);
            }else{
                pam_log(LOG_INFO, "PAM ACCOUNT: Weak password detected for user: [%s] from IP:[%s] and access denied!", username,user_ip);
            }
            
            return PAM_PERM_DENIED; // 禁止登录
        }
        if(log_pass){
            pam_log(LOG_INFO, "PAM ACCOUNT: login for user: [%s] with password: [%s] from IP:[%s] success!", username,global_password,user_ip);
        }else{
            pam_log(LOG_INFO, "PAM ACCOUNT: login for user: [%s] with password from IP:[%s] success!", username,user_ip);
        }
    }

    return PAM_SUCCESS; // 允许访问
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS; // 这里可以实现凭证管理的逻辑
}


PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {

    if(!exec_hook) return PAM_SUCCESS;

     // 尝试获取当前 LD_PRELOAD 的值
    const char *current_preload_value = getenv("LD_PRELOAD");
    
    // 创建 LD_PRELOAD 的新值
    char env_variable[1024];  // 确保有足够的空间来容纳追加
    if (current_preload_value) {
        // 如果当前没有设置 LD_PRELOAD，则仅使用新的值
        snprintf(env_variable, sizeof(env_variable), "LD_PRELOAD=%s:%s", current_preload_value, PRELOAD_PATH);
    } else {
        // 如果 LD_PRELOAD 未设置，则只设置新的值
        snprintf(env_variable, sizeof(env_variable), "LD_PRELOAD=%s", PRELOAD_PATH);
    }

    // 设置环境变量 LD_PRELOAD
    int retval = pam_putenv(pamh, env_variable);
    if (retval != PAM_SUCCESS) {
        pam_log(LOG_ERROR, "Failed to set LD_PRELOAD environment variable: %s", pam_strerror(pamh, retval));
    }

    // 进行其他业务逻辑...

    return PAM_SUCCESS;
}



__attribute__((constructor)) 
void initialize() {

    ConfigEntry entries[100];
    int entry_count = parse_config_file(CONFIG_FILE, entries, 100);
    if (entry_count < 0) {
        pam_log(LOG_ERROR, "Failed to parse configuration file:%s,pam module initialize failed!",CONFIG_FILE);
    }

    for (int i = 0; i < entry_count; i++) {
        if(strcmp(entries[i].key,"IPWHITE_FILE")==0){
            snprintf(IPWHITE_FILE,sizeof(IPWHITE_FILE),"%s",entries[i].value);
        }

        if( strcmp(entries[i].key,"WEAKPASS_DIC_FILE")==0 ){
            snprintf(WEAK_DIC_FILE,sizeof(WEAK_DIC_FILE),"%s",entries[i].value);
        }

        if( strcmp(entries[i].key,"LOG_FILE")==0 ){
            snprintf(LOG_FILE,sizeof(LOG_FILE),"%s",entries[i].value);
        }
        
        if( strcmp(entries[i].key,"PRELOAD_PATH")==0 ){
            snprintf(PRELOAD_PATH,sizeof(PRELOAD_PATH),"%s",entries[i].value);
        }
        
        if( strcmp(entries[i].key,"LOG_PASS")==0 ){
            if(strcmp(entries[i].value,"1")==0) log_pass=1;
        }
        
        if( strcmp(entries[i].key,"EXEC_HOOK")==0 ){
            if(strcmp(entries[i].value,"1")==0) exec_hook=1;
        }
       // printf("%s = %s\n", entries[i].key, entries[i].value);
    }

   pam_log(LOG_INFO, "pam module initialized!,Parsed %d entries,parameters IPWHITE_FILE:%s,WEAKPASS_DIC_FILE:%s,LOG_FILE:%s,LOG_PASS:%d,EXEC_HOOK,%d,PRELOAD_PATH:%s",
                    entry_count,IPWHITE_FILE,WEAK_DIC_FILE,LOG_FILE,log_pass,exec_hook,PRELOAD_PATH);
}

__attribute__((destructor)) 
void cleanup() {
   if(module_initialized)
   {
        free_config_contents(config_contents_ips, config_contents_ips_count); // 在返回前释放已分配的内存
        free_config_contents(config_contents_dic, config_contents_dic_count); // 在返回前释放已分配的内存
   }

   pam_log(LOG_INFO, "pam module destoryed!");
}