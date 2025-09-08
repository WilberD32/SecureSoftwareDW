#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <limits>
#include <regex>
#include <cctype>

#if defined(_WIN32)
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

struct User {
    std::string username;
    std::string hashed_password;
    signed int mfa_number;
};

class Validation {
public:
    bool checkSqlInjection(const std::string& input) {
        if (input.find('/') != std::string::npos ||
            input.find('-') != std::string::npos ||
            input.find(';') != std::string::npos ||
            input.find('"') != std::string::npos) {
            std::cerr << "\nValidation failed: Input contains invalid characters." << std::endl;
            return false;
        }
        return true;
    }

    bool checkPasswordPolicy(const std::string& password) {
        if (password.length() < 8 || password.length() > 12) {
            std::cerr << "\nValidation failed: Password must be 8-12 characters long." << std::endl;
            return false;
        }

        bool hasUppercase = false;
        bool hasLowercase = false;
        bool hasNumeric = false;

        for (char c : password) {
            if (isupper(c)) {
                hasUppercase = true;
            } else if (islower(c)) {
                hasLowercase = true;
            } else if (isdigit(c)) {
                hasNumeric = true;
            }
        }

        if (!hasUppercase) {
            std::cerr << "\nValidation failed: Password must contain at least one uppercase letter." << std::endl;
            return false;
        }
        if (!hasLowercase) {
            std::cerr << "\nValidation failed: Password must contain at least one lowercase letter." << std::endl;
            return false;
        }
        if (!hasNumeric) {
            std::cerr << "\nValidation failed: Password must contain at least one numeric character." << std::endl;
            return false;
        }

        return true;
    }

    bool checkIntegerOverflow(const std::string& input_str, signed int& output_int) {
        try {
            long long temp_ll = std::stoll(input_str);
            if (temp_ll < std::numeric_limits<signed int>::min() || 
                temp_ll > std::numeric_limits<signed int>::max()) {
                std::cerr << "\nValidation failed: Integer overflow. The number is out of signed int range." << std::endl;
                return false;
            }

            if (input_str.length() != 10) {
                 std::cerr << "\nValidation failed: MFA must be a 10-digit number." << std::endl;
                return false;
            }

            output_int = static_cast<signed int>(temp_ll);
            return true;
        } catch (const std::out_of_range& oor) {
            std::cerr << "\nValidation failed: The number is too large or too small to fit in a signed int. " << std::endl;
            return false;
        } catch (const std::invalid_argument& ia) {
            std::cerr << "\nValidation failed: Invalid input. Must be a number." << std::endl;
            return false;
        }
    }
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
#if defined(_WIN32)
    char ch;
    while ((ch = _getch()) != '\r' && ch != '\n') {
        if (ch == 8 || ch == 127) {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        } else if (ch == 3) {
            exit(1);
        } else {
            password += ch;
            std::cout << "*";
        }
    }
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    char ch;
    while (true) {
        ch = getchar();
        if (ch == '\n' || ch == EOF) break;
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
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    std::cout << std::endl;
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
        {"scientist", simple_hash("password123"), 1234567890},
        {"engineer", simple_hash("DevPass1!"), 1000000001},
        {"security", simple_hash("SecurePass!1"), 1000000002}
    };

    for (const auto& user : default_users) {
        outfile << user.username << " " << user.hashed_password << " " << user.mfa_number << std::endl;
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
    signed int mfa_number;
    while (infile >> username >> hashed_password) {
        if (infile >> mfa_number) {
            users.push_back({username, hashed_password, mfa_number});
        } else {
            // If no MFA number, use a default (e.g., 0)
            users.push_back({username, hashed_password, 0});
            // Clear error state for next read
            infile.clear();
        }
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
    
    Validation validator;

    const int max_login_attempts = 3;
    int login_attempts = 0;
    
    std::cout << "Welcome to the Secure Login Module" << std::endl;

    while (login_attempts < max_login_attempts) {
        std::string username_input, password_input, mfa_input;
        
        std::cout << "\nEnter username: ";
        std::cin >> username_input;

        if (!validator.checkSqlInjection(username_input)) {
            login_attempts++;
            std::cerr << "Username validation failed. Please try again. ("
                      << max_login_attempts - login_attempts << " attempts remaining)" << std::endl;
            continue;
        }
        
        std::cout << "Enter password: ";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        password_input = get_secure_password();

        if (!validator.checkSqlInjection(password_input) || !validator.checkPasswordPolicy(password_input)) {
            login_attempts++;
            std::cerr << "Password validation failed. Please try again. ("
                      << max_login_attempts - login_attempts << " attempts remaining)" << std::endl;
            continue;
        }

        std::cout << "Enter 10-digit MFA number: ";
        std::cin >> mfa_input;

        signed int mfa_number_input;
        if (!validator.checkIntegerOverflow(mfa_input, mfa_number_input)) {
            login_attempts++;
            std::cerr << "MFA validation failed. Please try again. ("
                      << max_login_attempts - login_attempts << " attempts remaining)" << std::endl;
            continue;
        }
        
        bool login_successful = false;
        for (const auto& user : users) {
            if (user.username == username_input) {
                if (simple_hash(password_input) == user.hashed_password && mfa_number_input == user.mfa_number) {
                    login_successful = true;
                    std::cout << "\n\nLogin successful!" << std::endl;
                    std::cout << "Welcome, " << user.username << "!" << std::endl;
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
