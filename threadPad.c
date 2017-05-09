//ThreadSearch.c
//Author JP Scaduto
/*
1) The search works by compiling the file and ignoring the warnings. 
2) after it is compiled, call the function ./a.out followed by the begining and end range
i.e. ./a.out 0 20000 to search 0 to 20,0000

This can be implemented by replacing the searches between bounds for s_i

if padding oracle implemented it will end when satisfied and return the integer that is correct.
*/
#include <string.h>
#include <stdio.h>
#include <pthread.h>
int threadSearch(int start,int end);
void *searching(void* arg);
int atoi(char* arg);
#define MAX_THREADS 100
#define NUM_THREADS 100
#define TEXT_LEN 1000000



//Global Variables shared by threads
int numthreads = NUM_THREADS;
int increment = NUM_THREADS; 
int done = 0;
int result = -1; // a positive value indicates the location of the match


struct position
{
	int pos;
	int checked; 
};

struct position pdx; //position
struct position * ptr=&pdx; //position pointer

pthread_mutex_t lock; //lock var
pthread_cond_t cond; //done?

int main(int argc, char *argv[]) {
	 // Step 1: Extract the pattern string from the command line.  
    int startNum = atoi(argv[1]);
    int endNum = atoi(argv[2]);
    printf("%d %d\n",startNum, endNum );
   	numthreads = NUM_THREADS;
    int res = threadSearch(startNum, endNum);
}

int threadSearch(int start, int end){
    pthread_t tids[numthreads]; //thread ID's
    ptr->pos = start; //init
    ptr->checked = 0; //init
    //printf("%d\n",patlen );
   	int j;
    for(j = 0;j<numthreads;j++){
    	pthread_create(&tids[j],NULL,searching,end); //create
    	//printf("%d\n",j );
    }
    for(j = 0;j<numthreads;j++){ 
    	pthread_join(tids[j],NULL); //begin
    	//printf("%d\n",j );
    }
   

   // Step 4: Determine the result and print it

    if (result == -1)
        printf("Number not found\n");
    else
        printf("s_1 == %d\n", result);
    return result;

}
	
int padding_oracle(int i){
    //if(i==15000){
      //  return 1;
    //}
    //make a padding oracle so that if the decryption of c_0 * i^e mod n is decrypted something that is padded correctly it will return 1
    return 0;
}

void * searching(void * arg){
	pthread_mutex_lock(&lock); //lock variable
	int ind;
	if(ptr->checked==1){ //check if was used
		ptr->pos++; //iterate to next
		ptr->checked=0; //clear
		ind = ptr->pos; //use
		ptr->checked = 1; //recheck
	}
	else{
		ind = ptr->pos; //not used so use
		ptr->checked = 1; //check as used
	}
	int y = (int)arg;
    //printf("%d\n",y );
	pthread_mutex_unlock(&lock); //uncheck
	while(ind<=y && !done) { //until end of text
		//printf("%d\n",textlen-patlen );
        printf("%d\n",ind );
		if (padding_oracle(ind) == 1) { //if found
			result = ind; //result = index
			done = 1; //done
			pthread_cond_broadcast(&cond); //tell all done
			break;
		}
		//printf("%d\n",ind );
		ind = ind+increment; //iterate to next index by the increment of number of threads so there is no collision

	}
	return NULL;

}