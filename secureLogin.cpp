#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <limits>

struct User {
    std::string username;
    std::string hashed_password;
};


std::string simple_hash(const std::string& password) {
    long long hash = 0;
    for (char c : password) {
        hash = (hash * 31 + c) % 1000000007; 
    }
    return std::to_string(hash);
}

std::string get_secure_password() {
    std::string password;
    char ch;
    while ((ch = std::cin.get()) != '\n' && ch != EOF) {
        if (ch == 8 || ch == 127) {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b"; 
            }
        } else {
            password += ch;
            std::cout << "*"; 
        }
    }
    return password;
}


void initialize_user_database(const std::string& filename) {
    std::ifstream file_check(filename);
    if (file_check) {
        return;
    }
    
    std::ofstream outfile(filename);
    if (!outfile.is_open()) {
        std::cerr << "Error: Could not create or open the user database file." << std::endl;
        return;
    }

    std::vector<User> default_users = {
        {"scientist", simple_hash("password123")},
        {"engineer", simple_hash("devpass")},
        {"security", simple_hash("securepass!")}
    };

    for (const auto& user : default_users) {
        outfile << user.username << " " << user.hashed_password << std::endl;
    }

    outfile.close();
    std::cout << "User database created successfully." << std::endl;
}

std::vector<User> load_user_database(const std::string& filename) {
    std::vector<User> users;
    std::ifstream infile(filename);

    if (!infile.is_open()) {
        std::cerr << "Error: User database file not found. Initializing..." << std::endl;
        initialize_user_database(filename);
        infile.open(filename); 
        if (!infile.is_open()) {
             std::cerr << "Fatal Error: Failed to open user database after creation." << std::endl;
             return {}; 
        }
    }

    std::string username, hashed_password;
    while (infile >> username >> hashed_password) {
        users.push_back({username, hashed_password});
    }

    infile.close();
    return users;
}

int main() {
    const std::string db_filename = "user_data.txt";
    std::vector<User> users = load_user_database(db_filename);
    if (users.empty()) {
        std::cerr << "No user data available. Exiting." << std::endl;
        return 1;
    }
    const int max_login_attempts = 3;
    int login_attempts = 0;
    std::cout << "Welcome to the Login Module" << std::endl;
    while (login_attempts < max_login_attempts) {
        std::string username_input;
        std::string password_input;
        std::cout << "\nEnter username: ";
        std::cin >> username_input;
        std::cout << "Enter password: ";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        password_input = get_secure_password();
        bool login_successful = false;
        for (const auto& user : users) {
            if (user.username == username_input) {
                if (simple_hash(password_input) == user.hashed_password) {
                    std::cout << "\n\nLogin successful!" << std::endl;
                    std::cout << "Welcome, " << user.username << "!" << std::endl;
                    login_successful = true;
                }
                break;
            }
        }
        if (login_successful) {
            break;
        } else {
            login_attempts++;
            std::cout << "\n\nLogin failed. Please try again. ("
                      << max_login_attempts - login_attempts << " attempts remaining)" << std::endl;
            if (login_attempts >= max_login_attempts) {
                std::cout << "Maximum login attempts exceeded. Your account may be locked." << std::endl;
                return 1;
            }
        }
    }
    return 0;
}
