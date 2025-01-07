#ifndef CLIENT_H
#define CLIENT_H

/* send message (maximum size: 1024 bytes) */
int sndmsg(char msg[1024], int port); 

#endif