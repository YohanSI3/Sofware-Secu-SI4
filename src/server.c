#include "client.h"
#include "server.h"

int stopserver();

/* read message sent by client */
int getmsg(char msg_read[1024]);

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080

void uploadFile(const char *filename) {
    char buffer[1024];
    FILE *source_fp, *dest_fp;

    // Ouvrir le fichier source pour lecture
    source_fp = fopen(filename, "rb");
    if (source_fp == NULL) {
        perror("Error opening source file");
        return;
    }

    // Ouvrir un fichier destination pour simuler l'upload
    dest_fp = fopen("uploaded_file.bin", "wb");
    if (dest_fp == NULL) {
        perror("Error opening destination file");
        fclose(source_fp);
        return;
    }

    // Copier les données du fichier source vers le fichier destination
    int bytes_read;
    while ((bytes_read = fread(buffer, sizeof(char), sizeof(buffer), source_fp)) > 0) {
        fwrite(buffer, sizeof(char), bytes_read, dest_fp);
    }

    printf("File uploaded successfully: %s\n", filename);

    fclose(source_fp);
    fclose(dest_fp);
}

void startserver() {
    printf("Server started on port %d \n", PORT);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s -start               Start the server\n", argv[0]);
        printf("  %s -up <file>           Upload file directly to the server\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "-up") == 0 && argc == 3) {
        startserver();
        uploadFile(argv[2]);
    } else {
        printf("Unknown option or missing argument\n");
        printf("Usage:\n");
        printf("  %s -up <file>           Upload file directly to the server\n", argv[0]);
        printf("  %s -list                List the files stored by the employee on the server\n", argv[0]);
        printf("  %s -down <file>         Download file from the server\n", argv[0]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}