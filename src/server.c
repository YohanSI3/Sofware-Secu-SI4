#include "client.h"
#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <errno.h>

#define PORT 8080
#define DB_FILE "users.db"
#define STORAGE_PATH "./users"
#define SALT "random_salt" //Sel utilisé pour le hachage des mots de passe

int stopserver();

/* read message sent by client */
int getmsg(char msg_read[1024]);

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

void hash_password(const char *password, char *hashed_password) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    char salted_password[256];
    snprintf(salted_password, sizeof(salted_password), "%s%s", SALT, password);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, salted_password, strlen(salted_password));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&hashed_password[i * 2], "%02x", hash[i]);
    }
    hashed_password[hash_len * 2] = '\0';
}

int user_exists(const char *username) {
    FILE *db = fopen(DB_FILE, "r");
    if (!db) return 0;

    char line[256];
    while (fgets(line, sizeof(line), db)) {
        char stored_username[128];
        sscanf(line, "%127[^:]", stored_username);
        if (strcmp(username, stored_username) == 0) {
            fclose(db);
            return 1;
        }
    }

    fclose(db);
    return 0;
}

void create_user_directory(const char *username) {
    char user_dir[256];
    snprintf(user_dir, sizeof(user_dir), "%s/%s", STORAGE_PATH, username);

    if (mkdir(STORAGE_PATH, 0755) == -1 && errno != EEXIST) {
        perror("Erreur lors de la création du dossier de stockage");
        exit(EXIT_FAILURE);
    }

    if (mkdir(user_dir, 0755) == -1 && errno != EEXIST) {
        perror("Erreur lors de la création du dossier utilisateur");
        exit(EXIT_FAILURE);
    }
}

int create_user(const char *username, const char *password) {
    if (user_exists(username)) {
        printf("Erreur : L'utilisateur '%s' existe déjà.\n", username);
        return 0;
    }

    char hashed_password[65];
    hash_password(password, hashed_password);

    FILE *db = fopen(DB_FILE, "a");
    if (!db) {
        perror("Erreur lors de l'ouverture de la base de données");
        return 0;
    }

    fprintf(db, "%s:%s\n", username, hashed_password);
    fclose(db);

    create_user_directory(username);
    printf("Utilisateur '%s' créé avec succès.\n", username);
    return 1;
}

int login_user(const char *username, const char *password) {
    if (!user_exists(username)) {
        printf("Erreur : L'utilisateur '%s' n'existe pas.\n", username);
        return 0;
    }

    char hashed_password[65];
    hash_password(password, hashed_password);

    FILE *db = fopen(DB_FILE, "r");
    if (!db) {
        perror("Erreur lors de l'ouverture de la base de données");
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), db)) {
        char stored_username[128], stored_password[65];
        sscanf(line, "%127[^:]:%64s", stored_username, stored_password);

        if (strcmp(username, stored_username) == 0) {
            fclose(db);
            if (strcmp(hashed_password, stored_password) == 0) {
                printf("Connexion réussie pour '%s'.\n", username);
                return 1;
            } else {
                printf("Erreur : Mot de passe incorrect.\n");
                return 0;
            }
        }
    }

    fclose(db);
    return 0;
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
    } else if (strcmp(argv[1], "-create") == 0 && argc == 4) {
        create_user(argv[2], argv[3]);
    } else if (strcmp(argv[1], "-login") == 0 && argc == 4) {
        login_user(argv[2], argv[3]);
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