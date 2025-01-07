#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "server.h"

#define MAX_MSG_SIZE 1024
#define USER_DB "users.db"

// Hacher un mot de passe avec SHA256
void hash_password(const char *password, char *hash) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password, strlen(password), digest);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash + (i * 2), "%02x", digest[i]);
    }
    hash[SHA256_DIGEST_LENGTH * 2] = '\0';
}

// Vérifier l'existence d'un utilisateur et ses identifiants
int authenticate_user(const char *username, const char *password, int *is_new_user) {
    char line[MAX_MSG_SIZE], file_hash[MAX_MSG_SIZE], input_hash[MAX_MSG_SIZE];
    FILE *db = fopen(USER_DB, "a+");
    if (!db) {
        perror("Erreur lors de l'ouverture de la base de données");
        return 0;
    }

    hash_password(password, input_hash);

    while (fgets(line, sizeof(line), db)) {
        char stored_username[MAX_MSG_SIZE];
        sscanf(line, "%s %s", stored_username, file_hash);
        if (strcmp(stored_username, username) == 0) {
            fclose(db);
            if (strcmp(file_hash, input_hash) == 0) {
                *is_new_user = 0;
                return 1; // Authentification réussie
            }
            return 0; // Mot de passe incorrect
        }
    }

    // Nouvel utilisateur
    fprintf(db, "%s %s\n", username, input_hash);
    *is_new_user = 1;
    fclose(db);
    return 1;
}
// Gérer les requêtes
void handle_request(const char *msg) {
    char command[MAX_MSG_SIZE], username[MAX_MSG_SIZE], password[MAX_MSG_SIZE];
    char buffer[MAX_MSG_SIZE];

    sscanf(msg, "%[^:]:%[^:]:%s", command, username, password);

    if (strcmp(command, "LOGIN") == 0) {
        int is_new_user;
        if (authenticate_user(username, password, &is_new_user)) {
            snprintf(buffer, MAX_MSG_SIZE, "SUCCESS");
            if (is_new_user) {
                char user_dir[MAX_MSG_SIZE];
                snprintf(user_dir, MAX_MSG_SIZE, "mkdir -p db/%s", username);
                system(user_dir);
                printf("Nouvel utilisateur %s créé.\n", username);
            } else {
                printf("Utilisateur %s connecté.\n", username);
            }
        } else {
            snprintf(buffer, MAX_MSG_SIZE, "ERREUR : Mot de passe incorrect.");
        }
    } else if (strncmp(msg, "UPLOAD:", 7) == 0) {
        const char *filename = msg + 7;
        const char *filedata = strchr(filename, ':') + 1;
        char file[MAX_MSG_SIZE];

        sscanf(filename, "%[^:]", file);

        FILE *f = fopen(file, "wb");
        if (!f) {
            perror("Erreur lors de l'écriture du fichier");
            return;
        }

        fwrite(filedata, 1, strlen(filedata), f);
        fclose(f);
        printf("Fichier %s reçu et enregistré.\n", file);
    } else if (strcmp(msg, "LIST") == 0) {
        // Liste des fichiers
        system("ls > files.txt");
        printf("Liste des fichiers envoyée.\n");
    } else if (strncmp(msg, "DOWNLOAD:", 9) == 0) {
        // Télécharger un fichier
        const char *filename = msg + 9;
        FILE *file = fopen(filename, "rb");
        if (!file) {
            perror("Fichier introuvable");
            return;
        }

        char buffer[MAX_MSG_SIZE];
        fread(buffer, 1, MAX_MSG_SIZE, file);
        fclose(file);

        printf("Fichier %s préparé pour le téléchargement.\n", filename);
    } else {
        printf("Commande inconnue : %s\n", msg);
    }
    // Autres commandes (UPLOAD, LIST, DOWNLOAD)
    // ...
}

int main_server() {
    char buffer[MAX_MSG_SIZE];
    startserver(8080);
    /*if (startserver(8080) < 0) {
        fprintf(stderr, "Erreur lors du démarrage du serveur\n");
        return 1;
    }*/

    printf("Serveur en écoute sur le port 8080...\n");
    while (1) {
        if (getmsg(buffer) > 0) {
            handle_request(buffer);
        }
    }

    stopserver();
    return 0;
}