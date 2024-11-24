#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmp.h>
#include <time.h>

void menu(){
    printf( "Options:\n-i path Path to the input file\n-o path Path to the output file\n-k path Path to the key file\n-g length Perform RSA key-pair generation given a key length length\n-d Decrypt input and store results to output.\n-e Encrypt input and store results to output.\n-a Compare the performance of RSA encryption and decryption with three different key lengths (1024, 2048, 4096 key lengths) in terms of computational time.\n-h This help message");
}

//check that all required file paths have been specified
short check_requirements(char *in,char *out, char *key){

    if((key!= NULL) && (in!= NULL) && (out!= NULL)){
        return 1;
    }

    return 0;
}

void generate_prime(mpz_t res,int len, gmp_randstate_t state){
    mpz_t p; mpz_init(p);

    mpz_urandomb(p, state, len);//Generate a random number 
	mpz_nextprime(res, p); //Use the random number to find its closest prime
}

//The totient function
void lamda(mpz_t res, mpz_t p, mpz_t q){
    mpz_sub_ui(p,p,1);
    mpz_sub_ui(q,q,1);
    mpz_mul(res,p,q);
}

//Simple function to compare the gcd of two operators to 1 (C seriously needs a bool data type)
short gcd_one(mpz_t op1, mpz_t op2){
    mpz_t res; mpz_init(res);
    mpz_gcd(res,op1,op2);

    if(mpz_cmp_ui(res,1)==0){
        return 0;
    }

    return 1;

}

//Simple function to compare the mod of two operators to 0. Both this and gcd_one help facilitate later comparisons
short mod_zero(mpz_t op1, mpz_t op2){
    mpz_t res; mpz_init(res);
    mpz_mod(res,op1,op2);

    if(mpz_cmp_ui(res,0)==0){
        return 0;
    }
    return 1;
}


 void generate_key_pair(int key_length,char *pKey_file, char *sKey_file,gmp_randstate_t state){
    printf("Generating keys...\n");
    mpz_t pKey_exp; mpz_init(pKey_exp); //Public key
    mpz_t sKey_exp; mpz_init(sKey_exp); //Private (secret) key

    mpz_t p,q,n,lam; mpz_init(p); mpz_init(q); mpz_init(n); mpz_init(lam);

    generate_prime(p,key_length/2, state); //Generate our two primes
    generate_prime(q,key_length/2, state);

    mpz_mul(n,p,q);//N = p * q
    lamda(lam,p,q);//Lambda(N) = (p-1) * (q-1) 

    srand(524);//my fav number :)
    int pKey_exp_len = (rand() % 10000) + 3; //e having a short bit-length and small Hamming weight results in more efficient encryption (Wikipedia)

    //generate a random prime to use as the public key exponent
    generate_prime(pKey_exp, pKey_exp_len,state);


    //Make sure all conditions are met for e and lamda(N) to be co-prime
    while((gcd_one(pKey_exp,lam)!=0) || mod_zero(pKey_exp,lam)==0){
        generate_prime(pKey_exp, key_length,state);
    }

    // modular inverse of (e, lambda) is d or the private key exponent
    mpz_invert(sKey_exp,pKey_exp,lam);

    FILE *p_file,*s_file;
    p_file = fopen(pKey_file,"w");
    s_file = fopen(sKey_file,"w");

    gmp_fprintf(p_file,"%Zd\n%Zd",pKey_exp,n);
    printf("File: %s written successfully...\n",pKey_file);
    gmp_fprintf(s_file,"%Zd\n%Zd",sKey_exp,n);
    printf("File: %s written successfully...\n",sKey_file);

    fclose(p_file);
    fclose(s_file);

 }

void encrypt(char *in_file,char *out_file,char *key_file){
    printf("Encrypting...\n");
    FILE *in, *key;
    in = fopen(in_file,"r");
    key = fopen(key_file,"r");

    if(in == NULL ){
        printf("The input file does not exist...\n");
        return ;
    }

    if(key == NULL ){
        printf("The key file does not exist...\n");
        return ;
    }

    char txt[10000],buf[10000];
    memset(txt, 0, sizeof(txt)); //clear the buffers in order to avoid data  corruption
    memset(buf, 0, sizeof(buf));
    mpz_t cleart; mpz_init(cleart);
    mpz_t ciphert; mpz_init(ciphert);
    mpz_t exp; mpz_init(exp);
    mpz_t n; mpz_init(n);     
	
	//Go through the entire file (without using buffers like this it would stop at the first white space)
    while(fscanf(in,"%s", buf)!=EOF){
        strcat(buf," ");
        strcat(txt,buf);
    }
	
	//convert the string to a number
    mpz_set_str(cleart,txt,62);

    memset(txt, 0, sizeof(txt));
    memset(buf, 0, sizeof(buf));//clear the buffers once again
    fscanf(key,"%s\n%s",txt,buf);//read the keys
    mpz_set_str(exp,txt,0);
    mpz_set_str(n,buf,0);    
    mpz_powm(ciphert,cleart,exp,n);//the actual encryption - cleartext ^ exp mod n
   
    FILE *out;
    out = fopen(out_file,"w");

    gmp_fprintf(out,"%Zd",ciphert);

    printf("File: %s written successfully...\n",out_file);

    fclose(in);
    fclose(key);
    fclose(out);
}

void decrypt(char *in_file,char *out_file,char *key_file){
    printf("Decrypting...\n");
    FILE *in, *key;
    in = fopen(in_file,"r");
    key = fopen(key_file,"r");

    if(in == NULL ){
        printf("The input file does not exist...\n");
        return ;
    }

    if(key == NULL ){
        printf("The key file does not exist...\n");
        return ;
    }

    char txt[10000],buf[10000];
    memset(txt, 0, sizeof(txt));
    memset(buf, 0, sizeof(buf));
    mpz_t cleart; mpz_init(cleart);
    mpz_t ciphert; mpz_init(ciphert);
    mpz_t exp; mpz_init(exp);
    mpz_t n; mpz_init(n);     

    while(fscanf(in,"%s", buf)!=EOF){
        strcat(buf," ");
        strcat(txt,buf);
    }

    mpz_set_str(ciphert,txt,0);

    memset(txt, 0, sizeof(txt));
    memset(buf, 0, sizeof(buf));
    fscanf(key,"%s\n%s",txt,buf);
    mpz_set_str(exp,txt,0);
    mpz_set_str(n,buf,0);    

    mpz_powm(cleart,ciphert,exp,n); //the actual decryption - ciphertext ^ exp mod n
    mpz_get_str(txt,62,cleart);

    FILE *out;
    out = fopen(out_file,"w");

    fprintf(out,"%s",txt);

    printf("File: %s written successfully...\n",out_file);

    fclose(in);
    fclose(key);
    fclose(out);
}


int main( int argc, char *argv[]){

    char *in_file=NULL;
    char *out_file=NULL;
    char *key_file=NULL; 
    char *perf_file=NULL;//paths to input/output files and the file storing the key
    int key_length=1024; // default key length just in case stuff hits the fan

    char *default_pKey_path = "public.key"; //Specified key file names
    char *default_sKey_path = "private.key";
    

    gmp_randstate_t state;//Random state initialization
    gmp_randinit_mt(state); //Mersenne Twister algorithm for good randomness properties since we are dealing with cryptography.
    gmp_randseed_ui(state,(unsigned)time(NULL)); // Seed derived from system time

    printf("\n");
    printf("***************************************************\n");
    printf("*                                                 *\n");
    printf("*             SIMPLE RSA TOOLARA(TM)              *\n");
    printf("*        Created by: The Coolest HMMYtzhdes       *\n");
    printf("*     (Krhtikakhs Marios, Georgakopoulos Hlias)   *\n");
    printf("*                                                 *\n");
    printf("***************************************************\n");

    for(int i=0;i<argc;i++){

       //It prints the help message(Named it menu because this ece school, not art school and I am not creative at all...sorry)
       if(strcmp(argv[i],"-h")==0){
            menu();
            
       }

       if(strcmp(argv[i],"-i")==0){
            if(i+1>=argc || argv[i+1][0] == '-'){
                printf("Please provide a path for the input file!\n");
                return 1;
            }
            in_file = argv[i+1];
            i++;           
       }

        if(strcmp(argv[i],"-k")==0){
            if(i+1>=argc || argv[i+1][0] == '-'){
                printf("Please provide a key file!");
                return 1;
            }
            key_file = argv[i+1];
            i++;
        }

       if(strcmp(argv[i],"-o")==0){
         if(i+1>=argc || argv[i+1][0] == '-'){
                printf("Please provide a path for the output file!");
                return 1;
            }
            out_file = argv[i+1];
            i++;
       }

       if(strcmp(argv[i],"-g")==0){
            if(i+1>=argc){
                printf("Please provide a key length!");
                return 1;
            } 
            key_length = atoi(argv[i+1]);
            i++;
            //not sure if first check is needed must confirm
            if(key_length>4096 || (key_length % 1024) !=0){
                printf("Invalid key length...\nKeys must be 1024,2048 or 4096 bytes in size");
            }
            generate_key_pair(key_length,default_pKey_path,default_sKey_path,state); //generate the key pair
       }

       if(strcmp(argv[i],"-d")==0){
            //check to make sure all required files have been provided
            if(check_requirements(in_file,out_file,key_file)==0){
                printf("Invalid arguwrite_to_file(out_file,ciphert);ments...\nDecryption requires an input file, an output file and a key.\n For help use -h");
                return -2;
            }
            decrypt(in_file,out_file,key_file);
            
       }

       if(strcmp(argv[i],"-e")==0){
            //check to make sure all required files have been provided
            if(check_requirements(in_file,out_file,key_file)==0){
                printf("Invalid arguments...\nEncryption requires an input file, an output file and a key.\n For help use -h");
                return -2;
            }
            encrypt(in_file,out_file,key_file);
            
       }

       if(strcmp(argv[i],"-a")==0){
            if(i+1>=argc){
                printf("Please provide a path for the sample file!");
                return 1;
            }
            
            perf_file = argv[i+1];

            clock_t start, end;
            double cpu_time_used;
            
            start = clock();
            generate_key_pair(1024,"public_1024.key","private_1024.key",state);
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("Time elapsed: %f s\n",cpu_time_used);

            start = clock();
            encrypt(perf_file,"cipher_1024.txt","public_1024.key");
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("Time elapsed: %f s\n",cpu_time_used);
             
            start = clock();
            decrypt("cipher_1024.txt","clear_1024.txt","private_1024.key");
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("Time elapsed: %f s\n",cpu_time_used);

            start = clock();
            generate_key_pair(2048,"public_2048.key","private_2048.key",state);
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("Time elapsed: %f s\n",cpu_time_used);

            start = clock();
            encrypt(perf_file,"cipher_2048.txt","public_2048.key");
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("Time elapsed: %f s\n",cpu_time_used);

            start = clock();
            decrypt("cipher_2048.txt","clear_2048.txt","private_2048.key");
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("Time elapsed: %f s\n",cpu_time_used);

            start = clock();
            generate_key_pair(4096,"public_4096.key","private_4096.key",state);
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("Time elapsed: %f s\n",cpu_time_used);

            start = clock();
            encrypt(perf_file,"cipher_4096.txt","public_4096.key");
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("Time elapsed: %f s\n",cpu_time_used);

            start = clock();
            decrypt("cipher_4096.txt","clear_4096.txt","private_4096.key");
            end = clock();
            cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
            printf("Time elapsed: %f s\n",cpu_time_used);
       }
    }

    return 0;
}
