#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <seccomp.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <mysql/mysql.h>

static void sandbox(){
    scmp_filter_ctx ctx;//Init the filter
    ctx = seccomp_init(SCMP_ACT_ALLOW);//default action: kill all the processes not in a whitelist

    if (!ctx)
        err(1, "seccomp_init failed");

    //setup the whitelist
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);

    // build and load the filter
    if (seccomp_load(ctx)) {
        perror("seccomp_load failed");
        exit(1);
    }
}

char* parse_hexdigest(const unsigned char* digest, const int length, char* hexdigest){
    hexdigest = (char*)malloc(length*2+1);
    memset(hexdigest, 0, length*2+1);
    for(int i = 0; i < length; i++){
        sprintf(hexdigest+i*2,"%02x",digest[i]);
    }
    printf("%s\n",hexdigest);
    return hexdigest;
}


void input(const char* username, const char* password)
{
    int i;
    int is_digit= 0;
    int is_small= 0;
    int is_cap= 0;

    printf("Your password should contain uppercase letter, lower case letters and digits, and be longer than 8 letters.\n");
    printf("username:");
    scanf("%s",username);

    for(;;){
        printf("password:");
        scanf("%s",password);
        if(strlen(password) > 8){
            while (password[i] != '\0') {
                if (password[i] >= 'A' && password[i] <= 'Z' && !is_cap)  //if there are caps
                    is_cap = 1;
                if (password[i] >= '0' && password[i] <= '9' && !is_digit) //if there are digits
                    is_digit = 1;
                if (password[i] >= 'a' && password[i] <= 'z' && !is_small) //if there are smalls
                    is_small = 1;
                i++;
            }
            if (is_small && is_cap && is_digit){
                break;
            }
        }
        printf("Your password is against the rule.\n");
    }
}

void read_database(){
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;

    char* server="localhost";//localhost
    char* user="Alice";//user
    char* password="Alice";//mysql password
    char* database="password";//database name
    char* query="select * from passwordstorage";//mysql query
    int t;

    conn=mysql_init(NULL);

    mysql_real_connect(conn,server,user,password,database,0,NULL,0);

    t=mysql_query(conn,query);

    if(t)
    {
        printf("Error making query:%s\n",mysql_error(conn));
    }else{
        printf("Query made...\n");
        res=mysql_use_result(conn);
        if(res)
        {
            while((row=mysql_fetch_row(res))!=NULL)
            {
                printf("    user       hash             salt\n");
                for(t=0;t<mysql_num_fields(res);t++)
                    printf("%8s ",row[t]);
                printf("\n");
            }
        }
        mysql_free_result(res);
    }
    mysql_close(conn);
}

void add_account(const char* username, char* digest, char* salt){
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;

    char* server="localhost";//localhost
    char* user="Alice";//user
    char* password="Alice";//mysql password
    char* database="password";//database name
    char* query[100];//
    int t;

    conn=mysql_init(NULL);

    mysql_real_connect(conn,server,user,password,database,0,NULL,0);

    sprintf(query,"insert into passwordstorage values('%s','%s','%s');",username, digest, salt);

    t=mysql_query(conn,query);
    if(t)
    {
        printf("Error making query:%s\n",mysql_error(conn));
    }else{
        printf("Query made...\n");
        res=mysql_use_result(conn);
        if(res)
        {
            while((row=mysql_fetch_row(res))!=NULL)
            {
                printf("    user       hash             salt\n");
                for(t=0;t<mysql_num_fields(res);t++)
                    printf("%8s ",row[t]);
                printf("\n");
            }
        }
        mysql_free_result(res);
    }
    mysql_close(conn);
}

void hash_add_account(const char* username, const char* password){
    const struct evp_md_st *outputBytes;
    unsigned char salt[8];
    int iter = 2048;
    int key_len = 8;
    unsigned char* digest;
    char hexdigest_salt;
    char hexdigest_digest;
    char* hexdigest_digest_p = &hexdigest_digest;
    char* hexdigest_salt_p = &hexdigest_salt;

    digest = (unsigned char *) malloc(sizeof(char) * key_len * 2);

    RAND_bytes(salt, sizeof(salt));

    printf("salt:");

    hexdigest_salt_p = parse_hexdigest(salt, sizeof(salt), hexdigest_salt_p);

    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, strlen(salt), iter, EVP_sha256(),key_len, digest);

    printf("Your username:%s\n", username);

    printf("hash:");

    hexdigest_digest_p = parse_hexdigest(digest, sizeof(digest), hexdigest_digest_p);

    add_account(username, hexdigest_digest_p, hexdigest_salt_p);

}

void hash_login(const char* username, const char* password){
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;

    char* server="localhost";//localhost
    char* user_database="Alice";//user
    char* password_database="Alice";//mysql password
    char* database="password";//database name
    char* query[100];
    int t;

    const struct evp_md_st *outputBytes;
    unsigned int i;
    unsigned char salt[8];
    unsigned char* digest;
    int iter = 2048;
    int key_len = 8;
    char hexdigest_digest;
    char* hexdigest_digest_p = &hexdigest_digest;
    char* hexdigest_salt_p[500];

    digest = (unsigned char *) malloc(sizeof(char) * key_len * 2);

    conn=mysql_init(NULL);

    mysql_real_connect(conn,server,user_database,password_database,database,0,NULL,0);

    sprintf(query,"select salt from passwordstorage where user = '%s';",username);

    t=mysql_query(conn,query);
    if(t)
    {
        printf("Error making query:%s\n",mysql_error(conn));
    }else{
        printf("Query made...\n");
        printf("salt:");
        res=mysql_use_result(conn);
        if(res)
        {
            while((row=mysql_fetch_row(res))!=NULL)
            {
                for(t=0;t<mysql_num_fields(res);t++)
                    printf("%8s ",row[t]);
                    sprintf(hexdigest_salt_p,"%8s ",row[t]);
                printf("\n");
            }
        }
        mysql_free_result(res);
    }
    mysql_close(conn);

    printf("login successfully");
}

void connect_to_database(){
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;

    char* server="localhost";
    char* user[20];//database user
    char* password[20];//database password
    char* database="password";//database name

    printf("app username:");
    scanf("%s",user);
    printf("app password:");
    scanf("%s",password);

    conn=mysql_init(NULL);

    if(!mysql_real_connect(conn,server,user,password,database,0,NULL,0))
    {
        printf("Error connecting to database:%s\n",mysql_error(conn));
    }else{
        printf("Connected...\n");
    }
    mysql_close(conn);
}

int main()
{
    const char username[20];
    const char password[20];
    unsigned char digest;
    const char *username_p = &username;
    const char *password_p = &password;
    unsigned char *digest_p = &digest;
    int option;
    sandbox();
    printf("please input your username and password to log into the database\n");
    connect_to_database();
    printf("---------------\n1.login\n2.add account\n3.read database\n---------------\n");
    scanf("%d",&option);
    switch (option)
    {
        case 1:
            input(username_p, password_p);
            hash_login(username_p, password_p);
            break;
        case 2:
            input(username_p, password_p);
            hash_add_account(username_p, password_p);
            break;
        case 3:
            read_database();
            break;
        default:
            printf("please choose again");
    }
    return 0;
}

