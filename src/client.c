#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include "client.h"

#define SERVER_PORT 8080
#define CLIENT_PORT 9090
#define MAX_MSG_SIZE 1024
#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

// Variables globales
char logged_in_user[MAX_MSG_SIZE] = "";
unsigned char aes_key[AES_KEY_SIZE];
int client_running = 1;

// Générer une clé AES aléatoire
void generate_aes_key() {
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        aes_key[i] = rand() % 256;
    }
}
int encrypt_file(const char *input_path, const char *output_path) {
    FILE *input = fopen(input_path, "rb");
    FILE *output = fopen(output_path, "wb");
    if (!input || !output) {
        perror("Erreur lors de l'ouverture des fichiers");
        return -1;
    }

    AES_KEY aes_enc_key;
    AES_set_encrypt_key(aes_key, AES_KEY_SIZE * 8, &aes_enc_key);

    unsigned char buffer[AES_BLOCK_SIZE];
    unsigned char encrypted[AES_BLOCK_SIZE];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, AES_BLOCK_SIZE, input)) > 0) {
        // Remplir le dernier bloc si nécessaire
        if (bytes_read < AES_BLOCK_SIZE) {
            memset(buffer + bytes_read, AES_BLOCK_SIZE - bytes_read, AES_BLOCK_SIZE - bytes_read);
            bytes_read = AES_BLOCK_SIZE;
        }
        AES_encrypt(buffer, encrypted, &aes_enc_key);
        fwrite(encrypted, 1, bytes_read, output);
    }

    fclose(input);
    fclose(output);
    return 0;
}

// Fonction pour déchiffrer un fichier
int decrypt_file(const char *input_path, const char *output_path) {
    FILE *input = fopen(input_path, "rb");
    FILE *output = fopen(output_path, "wb");
    if (!input || !output) {
        perror("Erreur lors de l'ouverture des fichiers");
        return -1;
    }

    AES_KEY aes_dec_key;
    AES_set_decrypt_key(aes_key, AES_KEY_SIZE * 8, &aes_dec_key);

    unsigned char buffer[AES_BLOCK_SIZE];
    unsigned char decrypted[AES_BLOCK_SIZE];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, AES_BLOCK_SIZE, input)) > 0) {
        AES_decrypt(buffer, decrypted, &aes_dec_key);
        fwrite(decrypted, 1, bytes_read, output);
    }

    fclose(input);
    fclose(output);
    return 0;
}

// Fonction pour vérifier si l'utilisateur est connecté
int is_logged_in() {
    return strlen(logged_in_user) > 0;
}

// Fonction de login
void login() {
    char username[MAX_MSG_SIZE], password[MAX_MSG_SIZE], buffer[MAX_MSG_SIZE];
    printf("Entrez votre nom d'utilisateur : ");
    if (fgets(username, sizeof(username), stdin) == NULL) {
        fprintf(stderr, "Erreur lors de la lecture du nom d'utilisateur\n");
        return;
    }
    username[strcspn(username, "\n")] = '\0';  // Retirer le caractère de nouvelle ligne

    printf("Entrez votre mot de passe : ");
    if (fgets(password, sizeof(password), stdin) == NULL) {
        fprintf(stderr, "Erreur lors de la lecture du mot de passe\n");
        return;
    }
    password[strcspn(password, "\n")] = '\0';  // Retirer le caractère de nouvelle ligne

    printf("test\n");
    snprintf(buffer, MAX_MSG_SIZE, "LOGIN:%s:%s", username, password);
    printf("%s", buffer);

    if (sndmsg(buffer, SERVER_PORT) < 0) {
        fprintf(stderr, "Erreur lors de l'envoi de la demande de connexion\n");
        return;
    }

    char response[MAX_MSG_SIZE];
    if (getmsg(response) > 0) {
        if (strcmp(response, "SUCCESS") == 0) {
            strcpy(logged_in_user, username);
            printf("Connexion réussie en tant que %s\n", username);
        } else {
            printf("Erreur : %s\n", response);
        }
    }
}

// Fonction pour uploader un fichier
void upload_file(const char *filename) {
    if (!is_logged_in()) {
        printf("Vous devez vous connecter pour uploader des fichiers.\n");
        return;
    }

    char encrypted_file[MAX_MSG_SIZE];
    snprintf(encrypted_file, sizeof(encrypted_file), "%s.enc", filename);

    if (encrypt_file(filename, encrypted_file) < 0) {
        printf("Erreur lors du chiffrement du fichier %s.\n", filename);
        return;
    }

    char buffer[MAX_MSG_SIZE];
    snprintf(buffer, MAX_MSG_SIZE, "UPLOAD:%s:%s", logged_in_user, filename);

    if (sndmsg(buffer, SERVER_PORT) < 0) {
        fprintf(stderr, "Erreur lors de l'envoi de la commande UPLOAD\n");
        return;
    }

    FILE *file = fopen(encrypted_file, "rb");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier chiffré");
        return;
    }

    while (fread(buffer, 1, MAX_MSG_SIZE, file) > 0) {
        sndmsg(buffer, SERVER_PORT);
    }

    printf("Fichier %s envoyé avec succès.\n", filename);
    fclose(file);
    remove(encrypted_file); // Supprimer le fichier temporaire
}

// Fonction pour demander la liste des fichiers
void list_files() {
    if (!is_logged_in()) {
        printf("Vous devez vous connecter pour lister vos fichiers.\n");
        return;
    }

    char buffer[MAX_MSG_SIZE];
    snprintf(buffer, MAX_MSG_SIZE, "LIST:%s", logged_in_user);

    if (sndmsg(buffer, SERVER_PORT) < 0) {
        fprintf(stderr, "Erreur lors de l'envoi de la commande LIST\n");
        return;
    }

    char response[MAX_MSG_SIZE];
    if (getmsg(response) > 0) {
        printf("Liste des fichiers :\n%s\n", response);
    } else {
        printf("Erreur lors de la réception de la liste des fichiers.\n");
    }
}

// Fonction pour télécharger un fichier
void download_file(const char *filename) {
    if (!is_logged_in()) {
        printf("Vous devez vous connecter pour télécharger des fichiers.\n");
        return;
    }

    char buffer[MAX_MSG_SIZE];
    snprintf(buffer, MAX_MSG_SIZE, "DOWNLOAD:%s:%s", logged_in_user, filename);

    if (sndmsg(buffer, SERVER_PORT) < 0) {
        fprintf(stderr, "Erreur lors de l'envoi de la commande DOWNLOAD\n");
        return;
    }

    char encrypted_file[MAX_MSG_SIZE];
    snprintf(encrypted_file, sizeof(encrypted_file), "%s.enc", filename);

    FILE *file = fopen(encrypted_file, "wb");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier pour écrire les données téléchargées");
        return;
    }

    char response[MAX_MSG_SIZE];
    while (getmsg(response) > 0) {
        fwrite(response, 1, strlen(response), file);
    }
    fclose(file);

    // Déchiffrer le fichier téléchargé
    if (decrypt_file(encrypted_file, filename) < 0) {
        printf("Erreur lors du déchiffrement du fichier téléchargé %s.\n", filename);
        return;
    }

    remove(encrypted_file); // Supprimer le fichier chiffré temporaire
    printf("Fichier %s téléchargé et déchiffré avec succès.\n", filename);
}

// Main
int main(int argc, char *argv[]) {
    if (startserver(CLIENT_PORT) < 0) {
        fprintf(stderr, "Erreur lors du démarrage du serveur client.\n");
        return 1;
    }

    generate_aes_key();

    printf("Bienvenue dans le client. En attente de commandes...\n");
    while (1) {
        char command[MAX_MSG_SIZE];
        printf("> ");
        fgets(command, MAX_MSG_SIZE, stdin);
        command[strcspn(command, "\n")] = 0; // Supprimer le saut de ligne

        if (strcmp(command, "login") == 0) {
            login();
        } else if (strncmp(command, "upload ", 7) == 0) {
            upload_file(command + 7);
        } else if (strcmp(command, "list") == 0) {
            list_files();
        } else if (strncmp(command, "download ", 9) == 0) {
            download_file(command + 9);
        } else if (strcmp(command, "exit") == 0) {
            client_running = 0;
            break;
        } else {
            printf("Commande inconnue. Utilisez login, upload <fichier>, list, download <fichier>, ou exit.\n");
        }
    }

    stopserver();
    return 0;
}