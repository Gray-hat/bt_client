#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <arpa/inet.h>

#include <openssl/sha.h> //hashing pieces

#include <time.h>

#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"



void calc_id(char * ip, unsigned short port, char *id){
  char data[256];
  int len;
  
  //format print
  len = snprintf(data,256,"%s%u",ip,port);

  //id is just the SHA1 of the ip and port string
  SHA1((unsigned char *) data, len, (unsigned char *) id); 

  return;
}


/**
 * init_peer(peer_t * peer, int id, char * ip, unsigned short port) -> int
 *
 *
 * initialize the peer_t structure peer with an id, ip address, and a
 * port. Further, it will set up the sockaddr such that a socket
 * connection can be more easily established.
 *
 * Return: 0 on success, negative values on failure. Will exit on bad
 * ip address.
 *   
 **/
int init_peer(peer_t *peer, char * id, char * ip, unsigned short port){
    
  struct hostent * hostinfo;
  //set the host id and port for referece
  memcpy(peer->id, id, ID_SIZE);
  peer->port = port;
    
  //get the host by name
  if((hostinfo = gethostbyname(ip)) ==  NULL){
    perror("gethostbyname failure, no such host?");
    herror("gethostbyname");
    exit(1);
  }
  
  //zero out the sock address
  bzero(&(peer->sockaddr), sizeof(peer->sockaddr));
      
  //set the family to AF_INET, i.e., Iternet Addressing
  peer->sockaddr.sin_family = AF_INET;
    
  //copy the address to the right place
  bcopy((char *) (hostinfo->h_addr), 
        (char *) &(peer->sockaddr.sin_addr.s_addr),
        hostinfo->h_length);
    
  //encode the port
  peer->sockaddr.sin_port = htons(port);
  
  return 0;

}

/**
 * print_peer(peer_t *peer) -> void
 *
 * print out debug info of a peer
 *
 **/
void print_peer(peer_t *peer){
  int i;

  if(peer){
    printf("peer: %s:%u ",
           inet_ntoa(peer->sockaddr.sin_addr),
           peer->port);
    printf("id: ");
    for(i=0;i<ID_SIZE;i++){
      printf("%02x",peer->id[i]);
    }
    printf("\n");
  }
}

/*
A function to parse the bencode tree to obtain the differenct values
returns 0 on success and -1 on failure
*/

int parse_bt_info(bt_info_t * bt_info, be_node * node, char * dict_key){

    int i;
    unsigned char * sha_temp;


    switch(node->type){
        case BE_DICT:

            for (i = 0; node->val.d[i].val; ++i) {
             
              parse_bt_info(bt_info, node->val.d[i].val, node->val.d[i].key);

            } 
            break;
        case BE_STR:
            if (!strcmp(dict_key,"announce")) {
                strcpy(bt_info->announce, node->val.s);
                printf("Announce tracker: %s\n", bt_info->announce);
            }
            if (!strcmp(dict_key, "name")) {
                strcpy(bt_info->name, node->val.s);
                printf("Name is: %s\n", bt_info->name);
            }
            if (!strcmp(dict_key, "pieces")) {
                bt_info->num_pieces = be_str_len(node)/20;
                printf("Number of pieces is %d\n", bt_info->num_pieces);
                bt_info->piece_hashes = malloc(bt_info->num_pieces * sizeof(unsigned char*)); //make space for the sha values
                for (i=0; i < bt_info->num_pieces; i++) {
                    sha_temp = malloc(20);
                    memcpy(sha_temp, node->val.s + i * 20, 20);
                    bt_info->piece_hashes[i] = sha_temp;
                }
            }
           
            break; 
        case BE_INT:
   
            if (!strcmp(dict_key, "length")) {
                bt_info->length += node->val.i;
                printf("The length is: %lld\n",bt_info->length);

            }
            if (!strcmp(dict_key, "piece length")) {
                bt_info->piece_length = node->val.i;
                printf("The length of a piece is: %d\n", bt_info->piece_length);
            }
            break;
        case BE_LIST:
           
            for (i = 0; node->val.l[i]; ++i){                
                parse_bt_info(bt_info,node->val.l[i],""); 

            }   
             
            break; 
        default:
            printf("Unexpected data in bencode in parse_bencode\n");
            break;

    }
    return 0;
}

/*
    add a peer to the peer pool if the peers haven't exceeded 5
*/

int add_peer(peer_t *peer, bt_args_t *bt_args, char * hostname, unsigned short port){

  int i, x;
  unsigned int id;
  char id_char;
  char *id_pointer;

  id = select_id();
  id_char = (char)id;
  id_pointer = &id_char;
  x = init_peer(peer, id_pointer, hostname, port);

  if (x == 0){
    for (i = 0; i < MAX_CONNECTIONS; i++){
      if (bt_args ->peers[i] == NULL){

        return 0;
      }
    }

    fprintf(stderr, "%s\n", "The peer pool is full. Try again later");
    return -1;
  } 
  else{
    exit(1);
  }

}

/*
Remove peer from those in the peer pool
*/
int drop_peer(peer_t *peer, bt_args_t *bt_args){

   int i;

  for (i = 0; i < MAX_CONNECTIONS; i++){
    if (bt_args ->peers[i] == peer){
      
      if (bt_args->verbose){
        printf("Peer  %s has successfully been removed \n", peer->id );
      }
      fprintf(stderr,"Peer %s has successfully been removed\n", peer->id );
      free(bt_args ->peers[i]);
      bt_args ->peers[i] = NULL;
      return 0;
    }
  }

  fprintf(stderr,"An error occurred while trying to remove peer %s\n", peer->id );
  return -1;


}

/*
Check if peer is still connected. This is essential done after
every minute
*/
int check_peer(peer_t *peer){

  bt_msg_t keep_alive;
  int response;

  keep_alive.length = 0;
  response = send_to_peer(peer, &keep_alive);
  if(response){
    fprintf(stderr, "check_peer: send_to_peer\n");
    return 1;
  }

  return 0;

}

/*
A random ID to serve as the identify for our node
*/
unsigned int select_id(){

  srand(time(NULL));
  unsigned int r = rand();

  return r;
}

int send_to_peer(peer_t * peer, bt_msg_t * msg){
  return 0;
}

int compute_info_hash(char *torrent_file, bt_info_t * bt_info){
    //get the torrent file and compute the SHA1 of the info value
  FILE *fp;
  int c;
  unsigned char sha_temp[20];
  int counter = 0;
  long int start =0;
  long int stop = 0;
  
  
  fp = fopen(torrent_file, "rb");
  if (fp == NULL){
    perror("Error opening file");

    return -1;
  }

  while ((c = fgetc(fp)) != EOF){
  
    if (counter == 4){
      start = ftell(fp) -1;
      break;
    }
    if(c == 'i' && counter == 0){
      counter += 1;
      continue;
    }
    if (c == 'n' && counter == 1){
      counter += 1;
      continue;
    }
    if (c == 'f' && counter == 2){
      counter += 1;
      continue;
    }
    if (c == 'o' && counter == 3){
      counter += 1;
      continue;
    }
      
    counter = 0;
  

  }
  fseek(fp, 0, SEEK_END);
  stop = ftell(fp);
 

  unsigned char info_dict[stop-start-1];
  fseek(fp, start, SEEK_SET);

  int i = 0;
  while ((c = fgetc(fp)) != EOF){

    info_dict[i] = c;
    i++;
  }
  info_dict[i] = '\0';
  fclose(fp);

  SHA1(info_dict, sizeof(info_dict), sha_temp);
  bt_info->info_hash = sha_temp;

  char out[41]; //null terminator
  for (i = 0; i < 20; i++) {
      snprintf(out+i*2, 3, "%02x", sha_temp[i]);
  }

 
  bt_info->info_hash_hex = out;

  return 0;

}
