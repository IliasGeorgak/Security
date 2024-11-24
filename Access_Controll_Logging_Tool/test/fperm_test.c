#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <grp.h>
#include <pwd.h>
#include <errno.h>
    
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

char paths[][256] = {
    "test/.testfiles/user_read.c",
    "test/.testfiles/group_read.c",
    "test/.testfiles/other_read.c",
    "test/.testfiles/user_write.c",
    "test/.testfiles/group_write.c",
    "test/.testfiles/other_write.c",
    "test/.testfiles/user_execute",
    "test/.testfiles/group_execute",
    "test/.testfiles/other_execute",
    "test/.testfiles/user_read_write.c",
    "test/.testfiles/group_read_write.c",
    "test/.testfiles/other_read_write.c",
    "test/.testfiles/user_read_execute",
    "test/.testfiles/group_read_execute",
    "test/.testfiles/other_read_execute",
    "test/.testfiles/user_write_execute",
    "test/.testfiles/group_write_execute",
    "test/.testfiles/other_write_execute"
};
/**
 * In this test we check whether our program can bypass permissions.
 * 
 * We have created 18 files with different permissions and we try to read, write and execute them.
*/


int testWrite(){
    for(int i = 0; i < 18; i++){
    
        FILE *fp = fopen(paths[i], "w");

        if (fp == NULL) {
            if (i == 3 || i == 9 || i == 15)
                return 0;
            else if (errno == EACCES)
                continue;
            else
                return 0;
        } else {
            if (i == 3 || i == 9 || i == 15)
                continue;
            else
                return 0;
        }
        errno = 0;
        if(fp != NULL)
            fclose(fp);
    }
    return 1;
}

int testRead(){
    for(int i = 0; i < 18; i++){
        FILE *fp = fopen(paths[i], "r");
        if (fp == NULL ){
            if (i == 0 || i == 9 || i == 12)
                return 0;
            else if (errno == EACCES)
                continue;
            else
                return 0;
        } else {
            if (i == 0 || i == 9 || i == 12)
                continue;
            else
                return 0;
        }
    }
    return 1;
}

int testExec(){
    for(int i = 0; i < 18; i++){
        char path[256] = "./";
        strcat(path, paths[i]);
        strcat(path, " ");
        strcat(path, paths[i]);
        strcat(path, " > /dev/null 2>&1");

        int exec = system(path);
        if (exec != 0 && (i == 6 || i == 12))
            return 0;
    }
    return 1;
}


int main() {
    FILE* fp = fopen("test/.testfiles/user_read.c", "r");
    fclose(fp);

    printf("%-20s : ", "Write");
    printf("[%4s]\n", testWrite() ? GRN "PASS" RESET : RED "FAIL" RESET);
    
    printf("%-20s : ", "Read");
    printf("[%4s]\n", testRead() ? GRN "PASS" RESET : RED "FAIL" RESET);

    printf("%-20s : ", "Exec");
    printf("[%4s]\n", testExec() ? GRN "PASS" RESET : RED "FAIL" RESET);
}