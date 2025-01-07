#ifndef CLIENT_H
#define CLIENT_H

/* send message (maximum size: 1024 bytes) */
int sndmsg(char msg[1024], int port); 

void generate_aes_key();

int rsa_encrypt(const char *pub_key_path, const unsigned char *data, size_t data_len, unsigned char *encrypted);

void login_user(const char *username, const char *password);

void upload_file(const char *file_path, const char *pub_key_path);

void download_file(const char *file_name);

void list_files();

#endif